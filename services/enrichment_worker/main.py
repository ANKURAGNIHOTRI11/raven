"""Opt-in, bounded CVE metadata enrichment. Does not publish events or touch graph/risk tables.

Dry-run is the default. --apply is required to write. Only descriptive metadata
(title, description, publication/modification timestamps and references) is
eligible for updates; scoring, affected-asset, graph, model and approval fields
are deliberately out of scope.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import asyncpg
import httpx

from raven_common.settings import get_settings

LOG = logging.getLogger("raven.enrichment_worker")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$", re.I)
USER_AGENT = "RAVEN-CVE-Enrichment/1.0 (+defensive-security; contact=maintainer)"
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
MAX_TEXT = 100_000
MAX_REFERENCES = 100


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split()).strip()
    if not value or "\x00" in value:
        return None
    return value[:limit]


def _timestamp(value: Any) -> datetime | None:
    """Convert ISO-8601 feed timestamps to datetime objects for asyncpg.

    PostgreSQL timestamptz parameters are encoded by asyncpg from Python
    datetime instances, not strings. Invalid or absent timestamps are ignored.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        candidate = value.strip()
        if candidate.endswith(("Z", "z")):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _url_refs(values: Any) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return refs
    seen: set[str] = set()
    for item in values:
        if isinstance(item, str):
            url, tags = item, []
        elif isinstance(item, dict):
            url = item.get("url")
            tags = item.get("tags", [])
        else:
            continue
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        refs.append({"url": url[:4096], "tags": tags if isinstance(tags, list) else []})
        if len(refs) >= MAX_REFERENCES:
            break
    return refs


def parse_nvd(data: dict[str, Any], cve_id: str) -> dict[str, Any]:
    items = data.get("vulnerabilities", [])
    if not isinstance(items, list):
        return {}
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        if str(cve.get("id", "")).upper() != cve_id.upper():
            continue
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list):
            descriptions = []
        description = next((_text(d.get("value")) for d in descriptions
                            if isinstance(d, dict) and d.get("lang") == "en"
                            and _text(d.get("value"))), None)
        refs = _url_refs(cve.get("references", []))
        return {
            "title": None,
            "description": description,
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "references": refs,
            "sources": ["NVD"],
        }
    return {}


def parse_ghsa(data: Any, cve_id: str) -> dict[str, Any]:
    if not isinstance(data, list):
        return {}
    for advisory in data:
        if not isinstance(advisory, dict):
            continue
        identifiers = advisory.get("identifiers", [])
        if not isinstance(identifiers, list):
            identifiers = []
        ids = {str(x.get("value", "")).upper() for x in identifiers if isinstance(x, dict)}
        if cve_id not in ids and str(advisory.get("cve_id", "")).upper() != cve_id:
            continue
        refs = _url_refs(advisory.get("references", []))
        return {
            "title": _text(advisory.get("summary")),
            "description": _text(advisory.get("description")),
            # Use the NVD publication timestamp, not GitHub's publication date.
            "published": advisory.get("nvd_published_at"),
            # GitHub updated_at is not the CVE's NVD lastModified timestamp.
            "modified": None,
            "references": refs,
            "sources": ["GitHub Security Advisories"],
        }
    return {}


def parse_osv(data: dict[str, Any], cve_id: str) -> dict[str, Any]:
    raw_aliases = data.get("aliases", [])
    aliases = [x.upper() for x in raw_aliases if isinstance(x, str)] if isinstance(raw_aliases, list) else []
    if cve_id not in aliases and str(data.get("id", "")).upper() != cve_id:
        return {}
    refs = _url_refs(data.get("references", []))
    return {
        "title": _text(data.get("summary")),
        "description": _text(data.get("details")),
        "published": data.get("published"),
        "modified": data.get("modified"),
        "references": refs,
        "sources": ["OSV"],
    }


async def _get_json(client: httpx.AsyncClient, url: str, *, params=None, headers=None):
    """Return (data, completed); 404 is a completed negative lookup."""
    try:
        response = await client.get(url, params=params, headers=headers)
        if response.status_code == 404:
            return None, True
        response.raise_for_status()
        data = response.json()
        if data is None:
            return None, False
        return data, True
    except (httpx.HTTPError, ValueError) as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        LOG.warning(
            "source_request_failed source_url=%s status=%s error=%s",
            url, status, type(exc).__name__,
        )
        return None, False


async def fetch_profile(
    client: httpx.AsyncClient,
    cve_id: str,
    nvd_key: str = "",
    github_token: str = "",
) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    nvd_headers = dict(headers)
    github_headers = {**headers, "Accept": "application/vnd.github+json"}
    if github_token:
        github_headers["Authorization"] = f"Bearer {github_token}"
    if nvd_key:
        nvd_headers["apiKey"] = nvd_key

    # Query sources independently: one outage must not discard the others.
    nvd_result, ghsa_result, osv_result = await asyncio.gather(
        _get_json(client, "https://services.nvd.nist.gov/rest/json/cves/2.0",
                  params={"cveId": cve_id}, headers=nvd_headers),
        _get_json(client, "https://api.github.com/advisories",
                  params={"cve_id": cve_id, "per_page": 10},
                  headers=github_headers),
        _get_osv(client, cve_id, headers),
    )
    nvd_data, nvd_ok = nvd_result
    ghsa_data, ghsa_ok = ghsa_result
    osv_data, osv_ok = osv_result

    nvd_ok = nvd_ok and (
        nvd_data is None or (
            isinstance(nvd_data, dict)
            and isinstance(nvd_data.get("vulnerabilities"), list)
            and all(isinstance(item, dict) for item in nvd_data["vulnerabilities"])
        )
    )
    ghsa_ok = ghsa_ok and (
        ghsa_data is None or (
            isinstance(ghsa_data, list)
            and all(isinstance(item, dict) for item in ghsa_data)
        )
    )
    parts = [
        parse_nvd(nvd_data, cve_id) if isinstance(nvd_data, dict) else {},
        parse_ghsa(ghsa_data, cve_id) if isinstance(ghsa_data, list) else {},
        parse_osv(osv_data, cve_id) if isinstance(osv_data, dict) else {},
    ]
    lookup_status = {"nvd": nvd_ok, "ghsa": ghsa_ok, "osv": osv_ok}
    profile: dict[str, Any] = {
        "sources": [],
        "references": [],
        "_lookup_complete": all(lookup_status.values()),
        "_failed_sources": [
            name for name, completed in lookup_status.items() if not completed
        ],
    }
    for part in parts:
        if not part:
            continue
        profile["sources"].extend(part.get("sources", []))
        for field in ("title", "description", "published", "modified"):
            if not profile.get(field) and part.get(field):
                profile[field] = part[field]
        profile["references"].extend(part.get("references", []))
    profile["references"] = _url_refs(profile["references"])
    profile["sources"] = sorted(set(profile["sources"]))
    # NVD commonly has a description but no title. Derive a display title only
    # from the first sentence of that source-backed description; never invent facts.
    if not profile.get("title") and profile.get("description"):
        first_sentence = re.split(r"(?<=[.!?])\s+", profile["description"], maxsplit=1)[0]
        profile["title"] = _text(first_sentence, 240)
    return profile


async def _get_osv(client: httpx.AsyncClient, cve_id: str, headers: dict):
    """Return (matching record, completed); 404 is a completed negative lookup."""
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 404:
            return None, True
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return None, False
        identifier_value = data.get("id")
        if not isinstance(identifier_value, str) or not identifier_value.strip():
            return None, False
        aliases = data.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(alias, str) for alias in aliases):
            return None, False
        identifier = identifier_value.upper()
        aliases = [alias.upper() for alias in aliases]
        if identifier == cve_id.upper() or cve_id.upper() in aliases:
            return data, True
        return None, True
    except (httpx.HTTPError, ValueError) as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        LOG.warning(
            "source_request_failed source_url=%s status=%s error=%s",
            url, status, type(exc).__name__,
        )
        return None, False


def _references_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().casefold() in {"", "null", "[]", "{}"}
    return value == [] or value == {}


def needs_enrichment(row: dict[str, Any]) -> bool:
    title = (row.get("title") or "").strip()
    cve_id = (row.get("cve_id") or "").strip()
    description = (row.get("description") or "").strip()
    return (not title or title.casefold() == cve_id.casefold() or not description
            or row.get("published") is None or row.get("modified") is None
            or _references_missing(row.get("references_json")))


def _can_record_no_match(profile: dict[str, Any]) -> bool:
    """Only completed source lookups can establish a definitive no-match."""
    return profile.get("_lookup_complete") is True


def _candidate_query(audit_table_exists: bool) -> str:
    """Build a read-only selection query that also works before audit-table creation.

    A seven-day cooldown applies to every recorded apply attempt, including
    partial fills, so an unavailable date field does not cause hot-loop refetches.
    """
    audit_filter = ""
    if audit_table_exists:
        audit_filter = """
          AND NOT EXISTS (
            SELECT 1
            FROM vulnerability_enrichment_audit AS recent_audit
            WHERE recent_audit.cve_id = vulnerabilities.cve_id
              AND recent_audit.completed_at >= now() - INTERVAL '7 days'
          )
        """
    return f"""
        SELECT cve_id, title, description, published, modified, references_json
        FROM vulnerabilities
        WHERE cve_id ~* '^CVE-[0-9]{{4}}-[0-9]{{4,7}}$'
          AND (
            NULLIF(BTRIM(title), '') IS NULL
            OR UPPER(BTRIM(title)) = UPPER(BTRIM(cve_id))
            OR NULLIF(BTRIM(description), '') IS NULL
            OR published IS NULL
            OR modified IS NULL
            OR references_json IS NULL
            OR references_json IN ('null'::jsonb, '[]'::jsonb, '{{}}'::jsonb)
          )
          {audit_filter}
        ORDER BY
          CASE
            WHEN NULLIF(BTRIM(title), '') IS NULL
              OR UPPER(BTRIM(title)) = UPPER(BTRIM(cve_id))
              OR NULLIF(BTRIM(description), '') IS NULL
            THEN 0
            WHEN published IS NULL OR modified IS NULL
            THEN 1
            ELSE 2
          END,
          cve_id
        LIMIT $1
        """


async def run_batch(limit: int, apply: bool) -> dict[str, int]:
    settings = get_settings()
    if not settings.pg_dsn:
        raise RuntimeError("RAVEN_PG_DSN is required; refusing to continue without a database DSN")
    counters = {"selected": 0, "matched": 0, "would_fill_title": 0,
                "would_fill_description": 0, "would_fill_dates": 0,
                "would_fill_references": 0, "updated": 0, "no_match": 0,
                "source_incomplete": 0}
    pool = await asyncpg.create_pool(settings.pg_dsn, min_size=1, max_size=3, command_timeout=30)
    try:
        async with pool.acquire() as conn:
            audit_table_exists = await conn.fetchval(
                "SELECT to_regclass('public.vulnerability_enrichment_audit') IS NOT NULL"
            )
            rows = await conn.fetch(_candidate_query(bool(audit_table_exists)), limit)
        counters["selected"] = len(rows)
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": USER_AGENT}) as client:
            for row_record in rows:
                row = dict(row_record)
                cve_id = row["cve_id"]
                if not CVE_RE.fullmatch(cve_id):
                    continue
                profile = await fetch_profile(
                    client, cve_id, settings.nvd_api_key,
                    github_token=settings.github_token,
                )
                if not profile.get("_lookup_complete", False):
                    counters["source_incomplete"] += 1
                title = profile.get("title")
                if title and title.casefold() == cve_id.casefold():
                    title = None
                description = profile.get("description")
                refs = profile.get("references", [])
                dates = bool(profile.get("published") or profile.get("modified"))
                missing_title = not (row.get("title") or "").strip() or (row.get("title") or "").strip().casefold() == cve_id.casefold()
                missing_description = not (row.get("description") or "").strip()
                refs_raw = row.get("references_json")
                # asyncpg returns JSONB as text unless a custom codec is installed.
                missing_refs = _references_missing(refs_raw)
                fill_title = bool(missing_title and title)
                fill_description = bool(missing_description and description)
                published = _timestamp(profile.get("published"))
                modified = _timestamp(profile.get("modified"))
                fill_dates = bool(
                    (row.get("published") is None and published is not None)
                    or (row.get("modified") is None and modified is not None)
                )
                fill_refs = bool(missing_refs and refs)
                if not (fill_title or fill_description or fill_dates or fill_refs):
                    counters["no_match"] += 1
                    if apply and _can_record_no_match(profile):
                        async with pool.acquire() as conn:
                            await conn.execute(
                                """
                                INSERT INTO vulnerability_enrichment_audit
                                  (cve_id, sources, fields_considered, applied,
                                   source_urls, completed_at)
                                VALUES ($1, $2::text[], $3::text[], FALSE,
                                        $4::jsonb, now())
                                """,
                                cve_id, profile.get("sources", []), [],
                                json.dumps(profile.get("references", [])),
                            )
                    elif apply:
                        LOG.info(
                            "no_match_audit_skipped_incomplete_lookup cve_id=%s failed_sources=%s",
                            cve_id, ",".join(profile.get("_failed_sources", [])),
                        )
                    continue
                counters["matched"] += 1
                counters["would_fill_title"] += int(fill_title)
                counters["would_fill_description"] += int(fill_description)
                counters["would_fill_dates"] += int(fill_dates)
                counters["would_fill_references"] += int(fill_refs)
                LOG.info("candidate cve_id=%s sources=%s fill_title=%s fill_description=%s fill_dates=%s fill_references=%s",
                         cve_id, ",".join(profile.get("sources", [])), fill_title,
                         fill_description, fill_dates, fill_refs)
                if not apply:
                    continue
                # Conditional field-by-field writes: existing nonempty values win.
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute(
                            """
                            UPDATE vulnerabilities SET
                              title = CASE WHEN (NULLIF(BTRIM(title), '') IS NULL OR UPPER(BTRIM(title)) = UPPER(BTRIM(cve_id)))
                                           AND $2::text IS NOT NULL THEN $2 ELSE title END,
                              description = CASE WHEN NULLIF(BTRIM(description), '') IS NULL
                                                 AND $3::text IS NOT NULL THEN $3 ELSE description END,
                              published = COALESCE(published, $4::timestamptz),
                              modified = COALESCE(modified, $5::timestamptz),
                              references_json = CASE WHEN (references_json IS NULL OR references_json IN ('null'::jsonb, '[]'::jsonb, '{}'::jsonb))
                                                      AND $6::jsonb <> '[]'::jsonb THEN $6::jsonb
                                                     ELSE references_json END,
                              normalized_at = now()
                            WHERE cve_id = $1
                            """,
                            cve_id, title, description, published, modified, json.dumps(refs),
                        )
                        await conn.execute(
                            """
                            INSERT INTO vulnerability_enrichment_audit
                              (cve_id, sources, fields_considered, applied, source_urls, completed_at)
                            VALUES ($1, $2::text[], $3::text[], TRUE, $4::jsonb, now())
                            """,
                            cve_id, profile.get("sources", []),
                            [name for name, ok in (("title", fill_title), ("description", fill_description),
                                                   ("dates", fill_dates), ("references", fill_refs)) if ok],
                            json.dumps(refs),
                        )
                counters["updated"] += 1
    finally:
        await pool.close()
    return counters


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=int(os.getenv("RAVEN_ENRICHMENT_BATCH_SIZE", "25")))
    parser.add_argument("--apply", action="store_true", help="write missing descriptive fields; default is dry-run")
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 500:
        parser.error("--limit must be between 1 and 500")
    logging.basicConfig(level=os.getenv("RAVEN_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.apply:
        settings = get_settings()
        if not settings.pg_dsn:
            raise RuntimeError("RAVEN_PG_DSN is required; refusing to create audit schema")
        pool = await asyncpg.create_pool(settings.pg_dsn, min_size=1, max_size=1)
        try:
            async with pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerability_enrichment_audit (
                      id BIGSERIAL PRIMARY KEY,
                      cve_id TEXT NOT NULL,
                      sources TEXT[] NOT NULL DEFAULT '{}',
                      fields_considered TEXT[] NOT NULL DEFAULT '{}',
                      applied BOOLEAN NOT NULL DEFAULT FALSE,
                      source_urls JSONB NOT NULL DEFAULT '[]',
                      completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                await conn.execute("CREATE INDEX IF NOT EXISTS vuln_enrich_audit_cve_idx ON vulnerability_enrichment_audit(cve_id, completed_at DESC)")
        finally:
            await pool.close()
    result = await run_batch(args.limit, args.apply)
    LOG.info("batch_complete mode=%s result=%s", "apply" if args.apply else "dry-run", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())

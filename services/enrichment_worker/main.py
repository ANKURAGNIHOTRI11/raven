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
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        if str(cve.get("id", "")).upper() != cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next((_text(d.get("value")) for d in descriptions
                            if isinstance(d, dict) and d.get("lang") == "en"
                            and _text(d.get("value"))), None)
        refs = _url_refs([r for r in cve.get("references", []) if isinstance(r, dict)])
        return {
            "title": _text(cve.get("sourceIdentifier")) if False else None,
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
        ids = {str(x.get("value", "")).upper() for x in identifiers if isinstance(x, dict)}
        if cve_id not in ids and str(advisory.get("cve_id", "")).upper() != cve_id:
            continue
        refs = _url_refs(advisory.get("references", []))
        return {
            "title": _text(advisory.get("summary")),
            "description": _text(advisory.get("description")),
            "published": advisory.get("published_at"),
            "modified": advisory.get("updated_at"),
            "references": refs,
            "sources": ["GitHub Security Advisories"],
        }
    return {}


def parse_osv(data: dict[str, Any], cve_id: str) -> dict[str, Any]:
    aliases = [str(x).upper() for x in data.get("aliases", []) if isinstance(x, str)]
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
    try:
        response = await client.get(url, params=params, headers=headers)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOG.warning("source_request_failed source_url=%s error=%s", url, type(exc).__name__)
        return None


async def fetch_profile(client: httpx.AsyncClient, cve_id: str, nvd_key: str = "") -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    nvd_headers = dict(headers)
    if nvd_key:
        nvd_headers["apiKey"] = nvd_key

    # Query sources independently: one outage must not discard the others.
    nvd_data, ghsa_data, osv_data = await asyncio.gather(
        _get_json(client, "https://services.nvd.nist.gov/rest/json/cves/2.0",
                  params={"cveId": cve_id}, headers=nvd_headers),
        _get_json(client, "https://api.github.com/advisories",
                  params={"cve_id": cve_id, "per_page": 10},
                  headers={**headers, "Accept": "application/vnd.github+json"}),
        _get_osv(client, cve_id, headers),
    )
    parts = [
        parse_nvd(nvd_data, cve_id) if isinstance(nvd_data, dict) else {},
        parse_ghsa(ghsa_data, cve_id),
        parse_osv(osv_data, cve_id) if isinstance(osv_data, dict) else {},
    ]
    profile: dict[str, Any] = {"sources": [], "references": []}
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
    return profile


async def _get_osv(client: httpx.AsyncClient, cve_id: str, headers: dict):
    try:
        response = await client.post(
            "https://api.osv.dev/v1/query",
            json={"cve": cve_id},
            headers=headers,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        # Prefer an exact CVE alias; validate again in parse_osv.
        for vuln in vulns:
            if isinstance(vuln, dict):
                aliases = [str(x).upper() for x in vuln.get("aliases", [])]
                if cve_id in aliases or str(vuln.get("id", "")).upper() == cve_id:
                    return vuln
        return None
    except (httpx.HTTPError, ValueError) as exc:
        LOG.warning("source_request_failed source_url=%s error=%s",
                    "https://api.osv.dev/v1/query", type(exc).__name__)
        return None


def needs_enrichment(row: dict[str, Any]) -> bool:
    title = (row.get("title") or "").strip()
    cve_id = (row.get("cve_id") or "").strip()
    description = (row.get("description") or "").strip()
    return (not title or title.casefold() == cve_id.casefold() or not description
            or row.get("published") is None or row.get("modified") is None
            or not row.get("references_json"))


async def run_batch(limit: int, apply: bool) -> dict[str, int]:
    settings = get_settings()
    if not settings.pg_dsn:
        raise RuntimeError("RAVEN_PG_DSN is required; refusing to continue without a database DSN")
    counters = {"selected": 0, "matched": 0, "would_fill_title": 0,
                "would_fill_description": 0, "would_fill_dates": 0,
                "would_fill_references": 0, "updated": 0, "no_match": 0}
    pool = await asyncpg.create_pool(settings.pg_dsn, min_size=1, max_size=3, command_timeout=30)
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT cve_id, title, description, published, modified, references_json
                FROM vulnerabilities
                WHERE cve_id ~* '^CVE-[0-9]{4}-[0-9]{4,7}$'
                  AND (
                    NULLIF(BTRIM(title), '') IS NULL OR UPPER(BTRIM(title)) = UPPER(BTRIM(cve_id))
                    OR NULLIF(BTRIM(description), '') IS NULL OR published IS NULL OR modified IS NULL
                    OR references_json IS NULL OR references_json = '[]'::jsonb
                  )
                ORDER BY cve_id
                LIMIT $1
                """,
                limit,
            )
        counters["selected"] = len(rows)
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": USER_AGENT}) as client:
            for row_record in rows:
                row = dict(row_record)
                cve_id = row["cve_id"]
                if not CVE_RE.fullmatch(cve_id):
                    continue
                profile = await fetch_profile(client, cve_id, settings.nvd_api_key)
                title = profile.get("title")
                if title and title.casefold() == cve_id.casefold():
                    title = None
                description = profile.get("description")
                refs = profile.get("references", [])
                dates = bool(profile.get("published") or profile.get("modified"))
                missing_title = not (row.get("title") or "").strip() or (row.get("title") or "").strip().casefold() == cve_id.casefold()
                missing_description = not (row.get("description") or "").strip()
                missing_refs = not row.get("references_json") or row.get("references_json") == []
                fill_title = bool(missing_title and title)
                fill_description = bool(missing_description and description)
                fill_dates = bool((row.get("published") is None and profile.get("published")) or
                                  (row.get("modified") is None and profile.get("modified")))
                fill_refs = bool(missing_refs and refs)
                if not (fill_title or fill_description or fill_dates or fill_refs):
                    counters["no_match"] += 1
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
                              references_json = CASE WHEN (references_json IS NULL OR references_json = '[]'::jsonb)
                                                      AND $6::jsonb <> '[]'::jsonb THEN $6::jsonb
                                                     ELSE references_json END,
                              normalized_at = now()
                            WHERE cve_id = $1
                            """,
                            cve_id, title, description, profile.get("published"),
                            profile.get("modified"), json.dumps(refs),
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

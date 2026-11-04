"""Opt-in, bounded CVE metadata enrichment. Does not publish events or touch graph/risk tables.

Dry-run is the default. --apply is required to write. Only descriptive metadata
(title, description, publication/modification timestamps and references) is
eligible for updates; scoring, affected-asset, graph, model and approval fields
are deliberately out of scope.
"""
from __future__ import annotations

import argparse
import hashlib
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

try:  # direct script execution (systemd) and package import (tests)
    from .public_sources import parse_circl_record, parse_cve_org_record
except ImportError:  # pragma: no cover - exercised by the host systemd entrypoint
    from public_sources import parse_circl_record, parse_cve_org_record

LOG = logging.getLogger("raven.enrichment_worker")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$", re.I)
USER_AGENT = "RAVEN-CVE-Enrichment/1.0 (+https://github.com/ANKURAGNIHOTRI11/raven)"
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
        if status in (401, 403):
            LOG.warning(
                "source_access_restricted source_url=%s status=%s",
                url, status,
            )
        else:
            LOG.warning(
                "source_request_failed source_url=%s status=%s error=%s",
                url, status, type(exc).__name__,
            )
        return None, False


async def _search_brave(
    client: httpx.AsyncClient,
    cve_id: str,
    api_key: str,
) -> tuple[list[dict[str, str]], bool]:
    """Discover public URLs; snippets are leads only, never metadata evidence."""
    query = f'"{cve_id}" vulnerability advisory vendor patch'
    url = "https://api.search.brave.com/res/v1/web/search"
    try:
        response = await client.get(
            url,
            params={"q": query, "count": 10, "search_lang": "en"},
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": api_key,
                "User-Agent": USER_AGENT,
            },
        )
        if response.status_code == 404:
            return [], True
        response.raise_for_status()
        data = response.json()
        web = data.get("web") if isinstance(data, dict) else None
        results = web.get("results") if isinstance(web, dict) else None
        if not isinstance(results, list):
            return [], False
        leads: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            result_url = item.get("url")
            if not isinstance(result_url, str) or not result_url.startswith(("https://", "http://")):
                continue
            if result_url in seen:
                continue
            seen.add(result_url)
            title = _text(item.get("title"), 300) or ""
            snippet = _text(item.get("description"), 700) or ""
            leads.append({
                "url": result_url[:4096],
                "title": title,
                "snippet": snippet,
                "status": "unverified_search_lead",
            })
            if len(leads) >= 10:
                break
        return leads, True
    except (httpx.HTTPError, ValueError) as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status in (401, 403):
            LOG.warning("search_access_restricted provider=brave status=%s", status)
        else:
            LOG.warning(
                "search_request_failed provider=brave status=%s error=%s",
                status, type(exc).__name__,
            )
        return [], False


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

    circl_url = f"https://vulnerability.circl.lu/api/vulnerability/{cve_id}"
    cve_org_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    circl_headers = dict(headers)
    circl_key = os.getenv("RAVEN_CIRCL_API_KEY", "")
    if circl_key:
        circl_headers["X-API-KEY"] = circl_key
    default_delay = "1.6" if circl_key else "3.1"
    try:
        circl_delay = max(0.0, float(os.getenv("RAVEN_CIRCL_REQUEST_DELAY_SECONDS", default_delay)))
    except ValueError:
        circl_delay = float(default_delay)
    # CIRCL's public instance documents 20 requests/minute anonymously and
    # 40/minute with an API key. The worker processes CVEs sequentially.
    if circl_delay:
        await asyncio.sleep(circl_delay)

    brave_key = os.getenv("RAVEN_BRAVE_SEARCH_API_KEY", "")
    if brave_key:
        brave_leads, brave_ok = await _search_brave(client, cve_id, brave_key)
    else:
        brave_leads, brave_ok = [], None

    # Each public endpoint is independent: a login wall, 404, rate limit, or
    # outage at one source must not discard evidence from another source.
    nvd_result, ghsa_result, osv_result, circl_result, cve_org_result = await asyncio.gather(
        _get_json(client, "https://services.nvd.nist.gov/rest/json/cves/2.0",
                  params={"cveId": cve_id}, headers=nvd_headers),
        _get_json(client, "https://api.github.com/advisories",
                  params={"cve_id": cve_id, "per_page": 10},
                  headers=github_headers),
        _get_osv(client, cve_id, headers),
        _get_json(client, circl_url, headers=circl_headers),
        _get_json(client, cve_org_url, headers=headers),
    )
    nvd_data, nvd_ok = nvd_result
    ghsa_data, ghsa_ok = ghsa_result
    osv_data, osv_ok = osv_result
    circl_data, circl_ok = circl_result
    cve_org_data, cve_org_ok = cve_org_result

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
    circl_ok = circl_ok and (circl_data is None or isinstance(circl_data, dict))
    cve_org_ok = cve_org_ok and (
        cve_org_data is None or isinstance(cve_org_data, dict)
    )

    parts = [
        parse_nvd(nvd_data, cve_id) if isinstance(nvd_data, dict) else {},
        parse_ghsa(ghsa_data, cve_id) if isinstance(ghsa_data, list) else {},
        parse_osv(osv_data, cve_id) if isinstance(osv_data, dict) else {},
        parse_circl_record(circl_data, cve_id, source_url=circl_url)
        if isinstance(circl_data, dict) else {},
        parse_cve_org_record(cve_org_data, cve_id, source_url=cve_org_url)
        if isinstance(cve_org_data, dict) else {},
    ]
    lookup_status = {
        "nvd": nvd_ok,
        "ghsa": ghsa_ok,
        "osv": osv_ok,
        "circl": circl_ok,
        "cve_org": cve_org_ok,
    }
    profile: dict[str, Any] = {
        "sources": [],
        "references": [],
        "field_evidence": {},
        "_conflicting_fields": {},
        "_lookup_complete": all(lookup_status.values()),
        "_source_status": lookup_status,
        "_failed_sources": [
            name for name, completed in lookup_status.items() if not completed
        ],
    }

    profile["discovery_leads"] = brave_leads
    profile["_optional_source_status"] = {
        "brave_search": (
            "not_configured" if brave_ok is None
            else ("ok" if brave_ok else "incomplete")
        )
    }
    if brave_leads:
        profile["field_evidence"]["discovery_leads"] = [{
            "source": "Brave Search (discovery only)",
            "source_url": "https://api.search.brave.com/res/v1/web/search",
            "classification": "unverified_search_leads",
            "results": brave_leads,
        }]

    def canonical(field: str, value: Any) -> str:
        if field in {"published", "modified"}:
            parsed = _timestamp(value)
            return parsed.isoformat() if parsed else str(value)
        if isinstance(value, str):
            return " ".join(value.split()).casefold()
        return json.dumps(value, sort_keys=True, default=str)

    for part in parts:
        if not part:
            continue
        source_names = part.get("sources", [])
        source_name = source_names[0] if source_names else "unknown"
        source_url = part.get("source_url", "")
        if not source_url:
            source_url = {
                "NVD": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                "GitHub Security Advisories": f"https://api.github.com/advisories?cve_id={cve_id}",
                "OSV": f"https://api.osv.dev/v1/vulns/{cve_id}",
            }.get(source_name, "")
        profile["sources"].extend(source_names)

        for field in ("title", "description", "published", "modified"):
            value = part.get(field)
            if value is None or value == "":
                continue
            evidence = profile["field_evidence"].setdefault(field, [])
            preview = str(value).replace("\n", " ").strip()[:500]
            evidence.append({
                "source": source_name,
                "source_url": source_url,
                "value_sha256": hashlib.sha256(str(value).encode("utf-8")).hexdigest(),
                "value_canonical_sha256": hashlib.sha256(canonical(field, value).encode("utf-8")).hexdigest(),
                "value_preview": preview,
            })
            if not profile.get(field):
                profile[field] = value

        source_refs = part.get("references", [])
        if source_refs:
            profile["references"].extend(source_refs)
            profile["field_evidence"].setdefault("references", []).append({
                "source": source_name,
                "source_url": source_url,
                "count": len(source_refs),
                "urls": [r["url"] for r in source_refs if isinstance(r, dict) and r.get("url")],
            })

    # Keep the highest-priority source value for preview, but mark any
    # disagreement. The write path suppresses conflicting fields.
    for field, evidence in profile["field_evidence"].items():
        if field == "references":
            continue
        distinct = {}
        for item in evidence:
            key = item.get("value_canonical_sha256") or canonical(field, item["value_preview"])
            distinct.setdefault(key, []).append(item)
        if len(distinct) > 1:
            profile["_conflicting_fields"][field] = [
                {
                    "source": item["source"],
                    "source_url": item["source_url"],
                    "value_preview": item["value_preview"],
                }
                for item in evidence
            ]

    profile["references"] = _url_refs(profile["references"])
    profile["sources"] = sorted(set(profile["sources"]))

    # NVD often has no title. A fallback title may be derived from the selected,
    # source-backed description, but its provenance is explicitly marked.
    if not profile.get("title") and profile.get("description"):
        first_sentence = re.split(r"(?<=[.!?])\s+", profile["description"], maxsplit=1)[0]
        derived = _text(first_sentence, 240)
        if derived:
            profile["title"] = derived
            profile["field_evidence"].setdefault("title", []).append({
                "source": "derived_from_description",
                "source_url": "",
                "value_sha256": hashlib.sha256(derived.encode("utf-8")).hexdigest(),
                "value_preview": derived,
            })
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
                "source_incomplete": 0, "conflict_fields": 0}
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
                conflicts = profile.get("_conflicting_fields", {})
                title = None if "title" in conflicts else profile.get("title")
                if title and title.casefold() == cve_id.casefold():
                    title = None
                description = None if "description" in conflicts else profile.get("description")
                refs = profile.get("references", [])
                missing_title = not (row.get("title") or "").strip() or (row.get("title") or "").strip().casefold() == cve_id.casefold()
                missing_description = not (row.get("description") or "").strip()
                refs_raw = row.get("references_json")
                # asyncpg returns JSONB as text unless a custom codec is installed.
                missing_refs = _references_missing(refs_raw)
                fill_title = bool(missing_title and title)
                fill_description = bool(missing_description and description)
                published = None if "published" in conflicts else _timestamp(profile.get("published"))
                modified = None if "modified" in conflicts else _timestamp(profile.get("modified"))
                fill_dates = bool(
                    (row.get("published") is None and published is not None)
                    or (row.get("modified") is None and modified is not None)
                )
                fill_refs = bool(missing_refs and refs)
                counters["conflict_fields"] += len(conflicts)
                if not (fill_title or fill_description or fill_dates or fill_refs):
                    if conflicts:
                        LOG.warning(
                            "candidate_has_conflicting_sources cve_id=%s fields=%s",
                            cve_id, ",".join(sorted(conflicts)),
                        )
                    counters["no_match"] += 1
                    if apply and _can_record_no_match(profile):
                        async with pool.acquire() as conn:
                            await conn.execute(
                                """
                                INSERT INTO vulnerability_enrichment_audit
                                  (cve_id, sources, fields_considered, applied,
                                   source_urls, field_evidence, source_status, completed_at)
                                VALUES ($1, $2::text[], $3::text[], FALSE,
                                        $4::jsonb, $5::jsonb, $6::jsonb, now())
                                """,
                                cve_id, profile.get("sources", []), [],
                                json.dumps(profile.get("references", [])),
                                json.dumps(profile.get("field_evidence", {})),
                                json.dumps({
                                    **profile.get("_source_status", {}),
                                    **profile.get("_optional_source_status", {}),
                                }),
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
                LOG.info(
                    "candidate cve_id=%s sources=%s fill_title=%s fill_description=%s "
                    "fill_dates=%s fill_references=%s conflicts=%s",
                    cve_id, ",".join(profile.get("sources", [])), fill_title,
                    fill_description, fill_dates, fill_refs,
                    ",".join(sorted(conflicts)),
                )
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
                              (cve_id, sources, fields_considered, applied,
                               source_urls, field_evidence, source_status, completed_at)
                            VALUES ($1, $2::text[], $3::text[], TRUE,
                                    $4::jsonb, $5::jsonb, $6::jsonb, now())
                            """,
                            cve_id, profile.get("sources", []),
                            [name for name, ok in (("title", fill_title), ("description", fill_description),
                                                   ("dates", fill_dates), ("references", fill_refs)) if ok],
                            json.dumps(refs),
                            json.dumps(profile.get("field_evidence", {})),
                            json.dumps({
                                **profile.get("_source_status", {}),
                                **profile.get("_optional_source_status", {}),
                            }),
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
                      field_evidence JSONB NOT NULL DEFAULT '{}',
                      source_status JSONB NOT NULL DEFAULT '{}',
                      completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                await conn.execute(
                    "ALTER TABLE vulnerability_enrichment_audit "
                    "ADD COLUMN IF NOT EXISTS field_evidence JSONB NOT NULL DEFAULT '{}'::jsonb"
                )
                await conn.execute(
                    "ALTER TABLE vulnerability_enrichment_audit "
                    "ADD COLUMN IF NOT EXISTS source_status JSONB NOT NULL DEFAULT '{}'::jsonb"
                )
                await conn.execute("CREATE INDEX IF NOT EXISTS vuln_enrich_audit_cve_idx ON vulnerability_enrichment_audit(cve_id, completed_at DESC)")
        finally:
            await pool.close()
    result = await run_batch(args.limit, args.apply)
    LOG.info("batch_complete mode=%s result=%s", "apply" if args.apply else "dry-run", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())

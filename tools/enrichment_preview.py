"""Read-only operator preview for EPIC-01 public-source metadata enrichment.

This command opens PostgreSQL in a read-only transaction, selects the same
bounded candidate set as the worker, queries the same public sources, and prints
the exact fields that would be eligible for fill. It never writes or creates
audit schema.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "libs" / "raven_common"))

import asyncpg
import httpx

from raven_common.settings import get_settings
from services.enrichment_worker import main as worker


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def build_preview(row: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Return review data and proposed missing fields without mutating either input."""
    cve_id = row["cve_id"]
    conflicts = profile.get("_conflicting_fields", {})
    title = None if "title" in conflicts else profile.get("title")
    if title and title.casefold() == cve_id.casefold():
        title = None
    description = None if "description" in conflicts else profile.get("description")
    published = (
        None if "published" in conflicts
        else worker._timestamp(profile.get("published"))
    )
    modified = (
        None if "modified" in conflicts
        else worker._timestamp(profile.get("modified"))
    )
    refs = profile.get("references", [])

    current_title = (row.get("title") or "").strip()
    current_description = (row.get("description") or "").strip()
    missing_title = not current_title or current_title.casefold() == cve_id.casefold()
    missing_description = not current_description
    missing_refs = worker._references_missing(row.get("references_json"))

    proposed: dict[str, Any] = {}
    if missing_title and title:
        proposed["title"] = title
    if missing_description and description:
        proposed["description"] = description
    if row.get("published") is None and published is not None:
        proposed["published"] = published.isoformat()
    if row.get("modified") is None and modified is not None:
        proposed["modified"] = modified.isoformat()
    if missing_refs and refs:
        proposed["references"] = refs

    return {
        "cve_id": cve_id,
        "sources_with_matching_records": profile.get("sources", []),
        "source_status": profile.get("_source_status", {}),
        "optional_source_status": profile.get("_optional_source_status", {}),
        "lookup_complete": profile.get("_lookup_complete", False),
        "failed_sources": profile.get("_failed_sources", []),
        "existing_fields": {
            "title": "missing" if missing_title else "preserved",
            "description": "missing" if missing_description else "preserved",
            "published": "missing" if row.get("published") is None else "preserved",
            "modified": "missing" if row.get("modified") is None else "preserved",
            "references": "missing" if missing_refs else "preserved",
        },
        "conflicts": conflicts,
        "proposed_fields": proposed,
        "field_evidence": profile.get("field_evidence", {}),
        "discovery_leads": profile.get("discovery_leads", []),
    }


async def run(limit: int) -> int:
    settings = get_settings()
    if not settings.pg_dsn:
        raise RuntimeError("RAVEN_PG_DSN is required")

    conn = await asyncpg.connect(settings.pg_dsn, timeout=10)
    try:
        async with conn.transaction(readonly=True):
            audit_exists = await conn.fetchval(
                "SELECT to_regclass('public.vulnerability_enrichment_audit') IS NOT NULL"
            )
            rows = await conn.fetch(worker._candidate_query(bool(audit_exists)), limit)
    finally:
        await conn.close()

    output = []
    async with httpx.AsyncClient(
        timeout=worker.TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": worker.USER_AGENT},
    ) as client:
        for record in rows:
            row = dict(record)
            cve_id = row["cve_id"]
            if not worker.CVE_RE.fullmatch(cve_id):
                continue
            profile = await worker.fetch_profile(
                client,
                cve_id,
                settings.nvd_api_key,
                github_token=settings.github_token,
            )
            output.append(build_preview(row, profile))

    totals = {
        "selected": len(output),
        "lookup_incomplete": sum(not x["lookup_complete"] for x in output),
        "records_with_conflicts": sum(bool(x["conflicts"]) for x in output),
        "would_fill": {
            field: sum(field in x["proposed_fields"] for x in output)
            for field in ("title", "description", "published", "modified", "references")
        },
    }
    print(json.dumps(
        {"mode": "read-only-preview", "totals": totals, "records": output},
        indent=2,
        ensure_ascii=False,
        default=_json_default,
    ))
    print("PREVIEW COMPLETE: no database writes were performed.", file=sys.stderr)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.limit <= 10:
        parser.error("--limit must be between 1 and 10")
    asyncio.run(run(args.limit))


if __name__ == "__main__":
    main()

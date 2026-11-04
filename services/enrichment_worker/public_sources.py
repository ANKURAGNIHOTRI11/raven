"""Parsers for anonymous, public CVE record sources used as enrichment fallbacks.

These adapters only accept exact CVE identifier matches. They normalize CVE
Record Format 5.x and OSV-shaped records without treating search snippets as
authoritative vulnerability data.
"""
from __future__ import annotations

from typing import Any


def _text(value: Any, limit: int = 100_000) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split()).strip()
    if not value or "\x00" in value:
        return None
    return value[:limit]


def _references(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    result: list[dict[str, Any]] = []
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
        result.append({
            "url": url[:4096],
            "tags": tags if isinstance(tags, list) else [],
        })
        if len(result) >= 100:
            break
    return result


def _unwrap_record(data: Any) -> dict[str, Any] | None:
    """Unwrap known single-record API envelopes without guessing arbitrary keys."""
    if not isinstance(data, dict):
        return None
    record = data
    for key in ("vulnerability", "record", "data"):
        nested = record.get(key)
        if isinstance(nested, dict):
            record = nested
            break
    return record


def parse_cve_record(
    data: Any,
    cve_id: str,
    *,
    source_name: str,
    source_url: str,
) -> dict[str, Any]:
    """Parse a CVE Record Format 5.x document after exact ID verification."""
    record = _unwrap_record(data)
    if record is None:
        return {}
    metadata = record.get("cveMetadata")
    containers = record.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        return {}
    actual_id = metadata.get("cveId")
    if not isinstance(actual_id, str) or actual_id.upper() != cve_id.upper():
        return {}

    cna = containers.get("cna")
    if not isinstance(cna, dict):
        return {}
    if str(metadata.get("state", "")).upper() == "REJECTED":
        return {"sources": [source_name], "source_url": source_url}

    descriptions = cna.get("descriptions", [])
    if not isinstance(descriptions, list):
        descriptions = []
    description = next(
        (
            _text(item.get("value"))
            for item in descriptions
            if isinstance(item, dict)
            and str(item.get("lang", "")).lower().startswith("en")
            and _text(item.get("value"))
        ),
        None,
    )

    return {
        "title": _text(cna.get("title"), 240),
        "description": description,
        "published": metadata.get("datePublished"),
        "modified": metadata.get("dateUpdated"),
        "references": _references(cna.get("references", [])),
        "sources": [source_name],
        "source_url": source_url,
    }


def parse_circl_record(data: Any, cve_id: str, *, source_url: str) -> dict[str, Any]:
    """Parse a CIRCL Vulnerability-Lookup CVE 5.x or OSV-shaped response."""
    record = _unwrap_record(data)
    if record is None:
        return {}

    # CIRCL stores multiple advisory formats. Prefer strict CVE 5.x parsing.
    cve_record = parse_cve_record(
        record,
        cve_id,
        source_name="CIRCL Vulnerability-Lookup",
        source_url=source_url,
    )
    if cve_record:
        return cve_record

    identifier = record.get("id")
    aliases = record.get("aliases", [])
    if not isinstance(identifier, str):
        return {}
    if not isinstance(aliases, list) or any(not isinstance(x, str) for x in aliases):
        return {}
    known_ids = {identifier.upper(), *(x.upper() for x in aliases)}
    if cve_id.upper() not in known_ids:
        return {}

    return {
        "title": _text(record.get("summary"), 240),
        "description": _text(record.get("details")),
        "published": record.get("published"),
        "modified": record.get("modified"),
        "references": _references(record.get("references", [])),
        "sources": ["CIRCL Vulnerability-Lookup"],
        "source_url": source_url,
    }


def parse_cve_org_record(data: Any, cve_id: str, *, source_url: str) -> dict[str, Any]:
    """Parse the public MITRE CVE Services GET /api/cve/{id} response."""
    return parse_cve_record(
        data,
        cve_id,
        source_name="CVE.org CVE Services",
        source_url=source_url,
    )

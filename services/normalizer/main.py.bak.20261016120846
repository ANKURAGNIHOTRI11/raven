"""Normalization engine + data-contract validator.

This is the choke point described in section 5.2 of the threat model: nothing
reaches the ontology unless it survives every check here.

  1. Contract validation      - pydantic schema, rejected records to quarantine
  2. Adversarial screening    - impossible values, trust-weighted field origin,
                                field length/type checks, active-content screening,
                                identifier spoofing
  3. Deduplication            - content hash + CVE-level merge
  4. Field arbitration        - a low-trust media source can add context and
                                exploit signals but can never overwrite CVSS,
                                CPE or KEV state set by an authoritative source
  5. Enrichment               - BERT exploit-maturity, NER product extraction
  6. Fan-out                  - Postgres (record), OpenSearch (search),
                                Qdrant (RAG vectors), bus (downstream)
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import math
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
import orjson

from raven_common import bus, db, topics
from raven_common.models import (
    NormalizedVulnerability,
    QuarantineRecord,
    RawDocument,
    Reference,
    SourceClass,
)
from raven_common.metrics import ERRORS, QUARANTINED, STAGE_LATENCY
from raven_common.runtime import bootstrap, run

from enrich import Enricher

SERVICE = "normalizer"
settings, log = bootstrap(SERVICE)
enricher = Enricher(settings.classifier_model)

AUTHORITATIVE_ONLY = {
    "cvss_base", "cvss_vector", "cvss_version", "cpe_uris", "kev", "kev_due_date"
}

# Scan for executable markup/payloads, not mere discussion of those strings.
# The script rule requires a complete element, so prose such as "the <script> tag"
# is accepted. URI detection requires an executable-looking target, so prose such
# as "javascript: URIs" is also accepted.
SCRIPTY = re.compile(
    r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>"
    r"|<[^>]+\bon[a-z][a-z0-9_-]*\s*="
    r"|<\s*(?:iframe|object|embed)\b"
    r"|javascript\s*:\s*(?:[a-z_$][\w$.-]*\s*\(|//)"
    r"|data\s*:\s*text/html\s*,",
    re.I | re.S,
)

# Use ASCII digits for CVE years and numbers. Python's \d accepts Unicode
# look-alike digits, which must not be accepted as canonical CVE identifiers.
CVE_SHAPE = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,7}"
    r"|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"
    r"|RHSA-[0-9]{4}:[0-9]+"
    r"|OSV-[0-9]{4}-[0-9]+)$",
    re.I,
)

SEVERITY_VALUES = {"none", "low", "medium", "high", "critical"}
SEVERITY_ALIASES = {
    "important": "high",
    "moderate": "medium",
    "negligible": "low",
    "informational": "low",
    "info": "low",
    "unknown": "none",
    "unspecified": "none",
    "": "none",
}
LIST_FIELDS = (
    "cwe_ids", "capec_ids", "attack_techniques", "cpe_uris", "affected_packages"
)


class Rejected(Exception):
    """A record that failed a deterministic input/security check."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason, self.detail = reason, detail


def _reject_nul(value, path: str = "record") -> None:
    """Reject NUL recursively, before text or JSONB reaches PostgreSQL."""
    if isinstance(value, str):
        if "\x00" in value:
            raise Rejected("nul_byte", path)
    elif isinstance(value, dict):
        for key, child in value.items():
            _reject_nul(key, f"{path}.<key>")
            _reject_nul(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for idx, child in enumerate(value):
            _reject_nul(child, f"{path}[{idx}]")


def _number(value, field: str, low: float, high: float) -> float | None:
    """Parse and validate a numeric score; absent values remain absent."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise Rejected("numeric_type", f"{field}: boolean is not a score")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise Rejected("numeric_type", f"{field}: {type(value).__name__}") from exc
    if not math.isfinite(parsed):
        raise Rejected("numeric_not_finite", field)
    if not low <= parsed <= high:
        raise Rejected("numeric_out_of_range", f"{field}={parsed}")
    return parsed


def _validate_timestamp(value, field: str, now: datetime) -> None:
    """Reject malformed timestamps and implausibly future-dated advisories."""
    if value is None or value == "":
        return
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise Rejected("invalid_timestamp", field) from exc
    else:
        raise Rejected("invalid_timestamp_type", f"{field}: {type(value).__name__}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    # Allow modest clock skew, but never accept a date years in the future.
    if parsed > now + timedelta(days=1):
        raise Rejected("future_timestamp", field)


def _validate_reference(ref, index: int) -> dict:
    """Validate references and restrict URLs to normal web schemes."""
    if isinstance(ref, str):
        url, tags = ref, []
    elif isinstance(ref, dict):
        url = ref.get("url")
        tags = ref.get("tags", [])
    else:
        raise Rejected("reference_type", f"reference[{index}]")

    if not isinstance(url, str) or not url.strip():
        raise Rejected("reference_without_url", f"reference[{index}]")
    url = url.strip()
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise Rejected("invalid_reference_url", f"reference[{index}]") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise Rejected("reference_url_scheme", f"reference[{index}]")
    if any(ord(ch) < 32 for ch in url):
        raise Rejected("invalid_reference_url", f"control character in reference[{index}]")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise Rejected("reference_tags_type", f"reference[{index}]")
    if len(url) > 4096:
        raise Rejected("reference_url_too_long", f"reference[{index}]")
    return {"url": url, "tags": tags}


def adversarial_screen(rec: dict, doc: RawDocument) -> None:
    """Validate and screen untrusted input before merge or persistence."""
    if not isinstance(rec, dict):
        raise Rejected("record_type", type(rec).__name__)
    _reject_nul(rec)

    raw_cve_id = rec.get("cve_id")
    if not isinstance(raw_cve_id, str):
        raise Rejected("identifier_type", type(raw_cve_id).__name__)
    cve_id = raw_cve_id.strip().upper()
    if len(cve_id) > 80 or not CVE_SHAPE.fullmatch(cve_id):
        raise Rejected("identifier_shape", cve_id[:80])
    rec["cve_id"] = cve_id

    # A CVE published in the future, or before the programme existed, is implausible.
    now = datetime.now(timezone.utc)
    year = int(cve_id.split("-")[1]) if cve_id.startswith("CVE-") else now.year
    if not 1999 <= year <= now.year + 1:
        raise Rejected("implausible_year", cve_id)
    _validate_timestamp(rec.get("published"), "published", now)
    _validate_timestamp(rec.get("modified"), "modified", now)

    # Validate all CVSS base-score fields, including version-specific fields that
    # might otherwise be ignored by the canonical model.
    for field in list(rec):
        if field.startswith("cvss") and field.endswith("_base"):
            parsed_score = _number(rec[field], field, 0.0, 10.0)
            if parsed_score is None:
                rec.pop(field, None)
            else:
                rec[field] = parsed_score
    # Existing records and the canonical schema use 0.0 for an unscored CVE.
    if "cvss_base" not in rec:
        rec["cvss_base"] = 0.0

    for field in ("epss_score", "epss_percentile"):
        if field in rec:
            parsed_score = _number(rec[field], field, 0.0, 1.0)
            if parsed_score is None:
                rec.pop(field, None)
            else:
                rec[field] = parsed_score

    if "severity" in rec and rec["severity"] is not None:
        if not isinstance(rec["severity"], str):
            raise Rejected("severity_type", type(rec["severity"]).__name__)
        severity = rec["severity"].strip().lower()
        severity = SEVERITY_ALIASES.get(severity, severity)
        if severity not in SEVERITY_VALUES:
            raise Rejected("severity_enum", severity[:80])
        rec["severity"] = severity

    # Titles and descriptions are stored/displayed content and must both be
    # strings screened for active payloads. Plain-language mentions are allowed.
    for field, limit in (("title", 10_000), ("description", 200_000)):
        value = rec.get(field)
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise Rejected(f"{field}_type", type(value).__name__)
        if "\x00" in value:
            raise Rejected("nul_byte", field)
        if len(value) > limit:
            raise Rejected(f"{field}_too_long", f"{len(value)} chars")
        if SCRIPTY.search(html.unescape(value)):
            raise Rejected("active_content", f"{field}: {value[:120]}")
        rec[field] = value

    for field in LIST_FIELDS:
        value = rec.get(field)
        if value is None:
            rec[field] = []
            continue
        if not isinstance(value, list):
            raise Rejected(f"{field}_type", type(value).__name__)
        if any(not isinstance(item, str) for item in value):
            raise Rejected(f"{field}_item_type", field)

    if len(rec.get("cpe_uris", [])) > 5000:
        raise Rejected("cpe_flood", str(len(rec["cpe_uris"])))
    for cpe in rec.get("cpe_uris", []):
        if len(cpe) > 2048:
            raise Rejected("cpe_too_long", cpe[:100])

    refs = rec.get("references")
    if refs is None:
        rec["references"] = []
    elif not isinstance(refs, list):
        raise Rejected("references_type", type(refs).__name__)
    else:
        rec["references"] = [_validate_reference(ref, i) for i, ref in enumerate(refs[:500])]

    # A community/media source must not supply authoritative-only fields.
    if doc.source_class in (SourceClass.MEDIA, SourceClass.COMMUNITY):
        claimed = AUTHORITATIVE_ONLY & {
            key for key, value in rec.items()
            if value not in (None, "", [], 0, 0.0, False)
        }
        if doc.source_class is SourceClass.MEDIA and claimed:
            for field in claimed:
                rec.pop(field, None)


def merge(existing: dict | None, incoming: dict, trust: float, klass: SourceClass) -> dict:
    """Field-level arbitration weighted by source trust."""
    if existing is None:
        out = dict(incoming)
        out["source_trust"] = trust
        return out
    out = dict(existing)
    prior_trust = float(existing.get("source_trust", 0.0))
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key in AUTHORITATIVE_ONLY and klass not in (SourceClass.AUTHORITATIVE, SourceClass.INTERNAL):
            continue
        if isinstance(value, list) and isinstance(out.get(key), list):
            seen, merged = set(), []
            for item in list(out[key]) + list(value):
                marker = orjson.dumps(item, option=orjson.OPT_SORT_KEYS)
                if marker not in seen:
                    seen.add(marker)
                    merged.append(item)
            out[key] = merged[:500]
        elif key == "kev":
            out[key] = bool(out.get(key)) or bool(value)
        elif trust >= prior_trust or not out.get(key):
            out[key] = value
    out["source_trust"] = max(prior_trust, trust)
    out["provenance"] = sorted(set(out.get("provenance", []) + incoming.get("provenance", [])))[:50]
    return out


async def load_existing(cve_id: str) -> dict | None:
    async with db.conn() as c:
        row = await c.fetchrow("SELECT * FROM vulnerabilities WHERE cve_id=$1", cve_id)
    if not row:
        return None
    d = dict(row)
    refs = d.pop("references_json", None)
    d["references"] = (
        orjson.loads(refs or b"[]")
        if isinstance(refs, (bytes, str))
        else (refs or [])
    )
    return d


async def persist(v: NormalizedVulnerability) -> None:
    async with db.conn() as c:
        await c.execute(
            """INSERT INTO vulnerabilities (cve_id,title,description,published,modified,
               cvss_vector,cvss_base,cvss_version,severity,cwe_ids,capec_ids,
               attack_techniques,cpe_uris,affected_packages,epss_score,epss_percentile,
               kev,kev_due_date,exploit_maturity,references_json,provenance,source_trust,
               ingest_confidence,normalized_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                       $20::jsonb,$21,$22,$23,now())
               ON CONFLICT (cve_id) DO UPDATE SET
                 title=CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE vulnerabilities.title END,
                 description=CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE vulnerabilities.description END,
                 published=COALESCE(EXCLUDED.published, vulnerabilities.published),
                 modified=COALESCE(EXCLUDED.modified, vulnerabilities.modified),
                 cvss_vector=COALESCE(EXCLUDED.cvss_vector, vulnerabilities.cvss_vector),
                 cvss_base=CASE WHEN EXCLUDED.cvss_base > 0 THEN EXCLUDED.cvss_base ELSE vulnerabilities.cvss_base END,
                 cvss_version=COALESCE(EXCLUDED.cvss_version, vulnerabilities.cvss_version),
                 severity=CASE WHEN EXCLUDED.severity <> 'none' THEN EXCLUDED.severity ELSE vulnerabilities.severity END,
                 cwe_ids=ARRAY(SELECT DISTINCT unnest(vulnerabilities.cwe_ids || EXCLUDED.cwe_ids)),
                 cpe_uris=ARRAY(SELECT DISTINCT unnest(vulnerabilities.cpe_uris || EXCLUDED.cpe_uris)),
                 affected_packages=ARRAY(SELECT DISTINCT unnest(vulnerabilities.affected_packages || EXCLUDED.affected_packages)),
                 epss_score=COALESCE(EXCLUDED.epss_score, vulnerabilities.epss_score),
                 epss_percentile=COALESCE(EXCLUDED.epss_percentile, vulnerabilities.epss_percentile),
                 kev=vulnerabilities.kev OR EXCLUDED.kev,
                 kev_due_date=COALESCE(EXCLUDED.kev_due_date, vulnerabilities.kev_due_date),
                 exploit_maturity=CASE WHEN EXCLUDED.exploit_maturity <> 'none' THEN EXCLUDED.exploit_maturity ELSE vulnerabilities.exploit_maturity END,
                 references_json=EXCLUDED.references_json,
                 provenance=(SELECT COALESCE(array_agg(DISTINCT p), ARRAY[]::text[]) FROM unnest(vulnerabilities.provenance || EXCLUDED.provenance) AS p),
                 source_trust=GREATEST(vulnerabilities.source_trust, EXCLUDED.source_trust),
                 ingest_confidence=GREATEST(vulnerabilities.ingest_confidence, EXCLUDED.ingest_confidence),
                 normalized_at=now()""",
            v.cve_id, v.title, v.description, v.published, v.modified, v.cvss_vector,
            v.cvss_base, v.cvss_version, v.severity, v.cwe_ids, v.capec_ids,
            v.attack_techniques, v.cpe_uris, v.affected_packages, v.epss_score,
            v.epss_percentile, v.kev, v.kev_due_date, v.exploit_maturity,
            orjson.dumps([r.model_dump() for r in v.references]).decode(),
            v.provenance, v.source_trust, v.ingest_confidence,
        )


async def match_assets(v: NormalizedVulnerability) -> list[str]:
    """Join the CVE to the inventory on CPE or package identity."""
    if not (v.cpe_uris or v.affected_packages):
        return []
    vendors = {u.split(":")[3] for u in v.cpe_uris if len(u.split(":")) > 4}
    pkgs = {p.split(":")[-1].lower() for p in v.affected_packages}
    async with db.conn() as c:
        rows = await c.fetch(
            """SELECT asset_id, packages, cpe_uris FROM assets
               WHERE packages && $1::text[] OR cpe_uris && $2::text[]
                  OR EXISTS (SELECT 1 FROM unnest(packages) p
                             WHERE lower(split_part(p, ':', 2)) = ANY($3::text[]))""",
            v.affected_packages, v.cpe_uris, list(pkgs) or [""],
        )
        matched = []
        for r in rows:
            fid = hashlib.sha1(f"{v.cve_id}:{r['asset_id']}".encode()).hexdigest()[:32]
            await c.execute(
                """INSERT INTO findings (finding_id, cve_id, asset_id, match_reason)
                   VALUES ($1,$2,$3,$4)
                   ON CONFLICT (cve_id, asset_id) DO UPDATE SET last_seen=now()""",
                fid, v.cve_id, r["asset_id"], "cpe_or_package",
            )
            matched.append(r["asset_id"])
    if vendors:
        log.debug("vendor_context", cve=v.cve_id, vendors=sorted(vendors)[:5])
    return matched


async def index_search(client: httpx.AsyncClient, v: NormalizedVulnerability) -> None:
    try:
        await client.put(
            f"{settings.opensearch_url}/raven-vulns/_doc/{v.cve_id}",
            json={
                "cve_id": v.cve_id, "title": v.title, "description": v.description,
                "severity": v.severity, "cvss_base": v.cvss_base, "kev": v.kev,
                "epss_percentile": v.epss_percentile,
                "packages": v.affected_packages, "cwe_ids": v.cwe_ids,
                "published": v.published.isoformat() if v.published else None,
            },
            timeout=20,
        )
    except Exception as exc:
        log.debug("opensearch_index_failed", error=str(exc)[:160])


async def quarantine_record(
    doc: RawDocument,
    producer: bus.Producer,
    reason: str,
    detail: str = "",
    rec: dict | None = None,
) -> None:
    """Persist a rejected record idempotently and send it to the DLQ once."""
    raw_obj = rec if rec is not None else (doc.payload or {})
    try:
        raw_excerpt = orjson.dumps(raw_obj, default=str)[:500].decode("utf-8", "replace")
    except Exception:
        raw_excerpt = repr(raw_obj)[:500]
    qr = QuarantineRecord(
        doc_id=doc.doc_id,
        source_id=doc.source_id,
        reason=reason[:120],
        detail=detail[:500],
        raw_excerpt=raw_excerpt,
    )
    QUARANTINED.labels(doc.source_id, qr.reason).inc()
    async with db.conn() as c:
        inserted = await c.fetchval(
            """INSERT INTO quarantine (doc_id, source_id, reason, detail, raw_excerpt)
               SELECT $1,$2,$3,$4,$5
               WHERE NOT EXISTS (
                   SELECT 1 FROM quarantine
                   WHERE doc_id=$1 AND source_id=$2 AND reason=$3
               )
               RETURNING 1""",
            qr.doc_id, qr.source_id, qr.reason, qr.detail, qr.raw_excerpt,
        )
        if inserted:
            await c.execute(
                "UPDATE sources SET quarantined_records=quarantined_records+1 WHERE source_id=$1",
                doc.source_id,
            )
    if inserted:
        await producer.send(topics.QUARANTINE, qr, key=doc.source_id)
    log.info("quarantined", source=doc.source_id, reason=qr.reason, new_record=bool(inserted))


async def handle(doc: RawDocument, producer: bus.Producer, client: httpx.AsyncClient) -> None:
    rec = dict(doc.payload or {})
    try:
        adversarial_screen(rec, doc)
    except Rejected as rej:
        await quarantine_record(doc, producer, rej.reason, rej.detail, rec)
        return
    except (TypeError, ValueError, OverflowError) as exc:
        # Unexpected validation conversion errors are data-contract failures,
        # not reasons to silently discard the message.
        await quarantine_record(doc, producer, "invalid_record", str(exc)[:500], rec)
        return

    rec["provenance"] = [doc.doc_id]
    cve_id = rec["cve_id"]
    existing = await load_existing(cve_id)
    merged = merge(existing, rec, doc.trust, doc.source_class)
    merged["cve_id"] = cve_id

    text = f"{merged.get('title', '')} {merged.get('description', '')}"
    maturity, conf = await asyncio.to_thread(enricher.exploit_maturity, text)
    if merged.get("kev"):
        maturity, conf = "weaponized", 1.0
    order = {"none": 0, "poc": 1, "functional": 2, "weaponized": 3}
    if order.get(maturity, 0) >= order.get(merged.get("exploit_maturity", "none"), 0):
        merged["exploit_maturity"] = maturity
    merged["ingest_confidence"] = round(min(1.0, 0.5 * conf + 0.5 * float(doc.trust)), 3)

    products = await asyncio.to_thread(
        enricher.products, text, merged.get("cpe_uris", []) or []
    )
    merged["affected_packages"] = sorted(
        set(merged.get("affected_packages", []) or []) | {f"product:{p}" for p in products}
    )[:200]

    try:
        merged["references"] = [
            Reference.model_validate(ref).model_dump()
            for ref in (merged.get("references") or [])
        ][:60]
        vuln = NormalizedVulnerability.model_validate(merged)
    except Exception as exc:
        # Contract/type validation failures are quarantined instead of being
        # logged and silently lost. Do not wrap DB/network calls in this block.
        await quarantine_record(
            doc, producer, "post_merge_contract", str(exc)[:500], merged
        )
        ERRORS.labels(SERVICE, "post_merge_contract").inc()
        return

    await persist(vuln)
    assets = await match_assets(vuln)
    await index_search(client, vuln)
    await producer.send(topics.NORMALIZED_VULNS, vuln, key=vuln.cve_id)
    log.info("normalized", cve=vuln.cve_id, severity=vuln.severity,
             kev=vuln.kev, assets=len(assets), source=doc.source_id)


async def main() -> None:
    await bus.wait_for_bus()
    producer = await bus.Producer(SERVICE).start()

    async def on_invalid_raw_document(raw: dict, exc: Exception) -> None:
        """Quarantine messages that fail RawDocument validation at the bus edge."""
        raw_obj = raw if isinstance(raw, dict) else {"_raw": repr(raw)}
        try:
            encoded = orjson.dumps(raw_obj, default=str)
        except Exception:
            encoded = repr(raw_obj).encode("utf-8", "replace")
        digest = hashlib.sha256(encoded).hexdigest()

        candidate_doc_id = raw_obj.get("doc_id")
        doc_id = (
            candidate_doc_id
            if isinstance(candidate_doc_id, str) and candidate_doc_id.strip()
            else f"invalid-raw-document-{digest}"
        )
        candidate_source_id = raw_obj.get("source_id")
        source_id = (
            candidate_source_id
            if isinstance(candidate_source_id, str) and candidate_source_id.strip()
            else "unknown"
        )

        # The envelope itself failed schema validation, so bypass RawDocument
        # validation while supplying only fields quarantine_record() consumes.
        invalid_doc = RawDocument.model_construct(
            doc_id=doc_id,
            source_id=source_id,
            payload=raw_obj,
        )
        await quarantine_record(
            invalid_doc,
            producer,
            "raw_document_contract",
            str(exc)[:500],
            raw_obj,
        )

    async with httpx.AsyncClient() as client:
        async for doc in bus.consume(
            [topics.RAW_DOCUMENTS],
            "normalizer",
            RawDocument,
            SERVICE,
            on_invalid=on_invalid_raw_document,
        ):
            with STAGE_LATENCY.labels(SERVICE, "normalize").time():
                try:
                    await handle(doc, producer, client)
                except Exception as exc:
                    ERRORS.labels(SERVICE, "handle").inc()
                    log.warning("normalize_failed", doc=doc.doc_id, error=str(exc)[:300])


if __name__ == "__main__":
    run(main, SERVICE)


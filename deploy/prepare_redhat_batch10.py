import asyncio
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from raven_common import db, storage
from parsers import parse_redhat

ROOT = Path("/workspace")
TARGET_COUNT = 10
MAX_TITLE_LENGTH = 120

NORM_FILE = ROOT / "raven_redhat_title_normalized_review.csv"
PREFLIGHT_FILE = ROOT / "raven_redhat_title_preflight.csv"
DEDUP_FILE = ROOT / "raven_redhat_title_review_dedup.csv"
DRYRUN_FILE = ROOT / "raven_redhat_title_dryrun.csv"

MANIFEST_FILE = ROOT / "raven_redhat_batch10_manifest.csv"
SNAPSHOT_FILE = ROOT / "raven_redhat_batch10_before.json"


def load_csv(path):
    if not path.is_file():
        raise SystemExit(f"STOP: required file is missing: {path.name}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def unique_map(rows, key, label):
    result = {}
    duplicates = []
    for row in rows:
        value = row.get(key, "").strip()
        if not value:
            raise SystemExit(f"STOP: blank {key} in {label}")
        if value in result:
            duplicates.append(value)
        result[value] = row
    if duplicates:
        raise SystemExit(
            f"STOP: duplicate {key} values in {label}: "
            + ", ".join(sorted(set(duplicates))[:10])
        )
    return result


def as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def to_jsonable(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


async def inspect_candidate(candidate, preflight, dedup, dryrun):
    cve = candidate["cve_id"].strip()
    title = candidate["normalized_candidate"].strip()
    reasons = []

    # This batch allows only unchanged source candidates.
    if candidate.get("review_status") != "REVIEW_SOURCE_CANDIDATE":
        reasons.append("not an unchanged source candidate")
    if candidate.get("original_candidate", "").strip() != title:
        reasons.append("candidate requires title normalization")
    if len(title) > MAX_TITLE_LENGTH:
        reasons.append("title exceeds length limit")
    if not title or title.casefold() == cve.casefold():
        reasons.append("candidate title is empty or still a CVE placeholder")
    if candidate.get("current_title", "").strip().casefold() != cve.casefold():
        reasons.append("review file current title is not a placeholder")
    if candidate.get("source_field", "").strip() != "bugzilla_description":
        reasons.append("unexpected source field")

    p = preflight.get(cve)
    d = dedup.get(cve)
    if p is None:
        reasons.append("no matching preflight row")
    else:
        if p.get("review_flags", "").strip():
            reasons.append("preflight flags are not blank")
        if p.get("source_doc_id", "").strip() != candidate.get("source_doc_id", "").strip():
            reasons.append("preflight source document ID differs")
        if p.get("source_object_key", "").strip() != candidate.get("source_object_key", "").strip():
            reasons.append("preflight archive key differs")
        if p.get("candidate_title", "").strip() != title:
            reasons.append("preflight candidate title differs")
        if p.get("current_title", "").strip().casefold() != cve.casefold():
            reasons.append("preflight current title is not a placeholder")

    if d is None:
        reasons.append("no matching deduplication row")
    else:
        if d.get("review_status") != "SINGLE_DISTINCT_CANDIDATE_REVIEW":
            reasons.append("candidate is not unique in the deduplication review")
        if d.get("distinct_candidate_count", "").strip() != "1":
            reasons.append("distinct candidate count is not one")
        if d.get("candidate_title", "").strip() != title:
            reasons.append("deduplicated candidate title differs")
        if d.get("current_title", "").strip().casefold() != cve.casefold():
            reasons.append("deduplication row current title is not a placeholder")
        if d.get("source_doc_id", "").strip() != candidate.get("source_doc_id", "").strip():
            reasons.append("deduplication source document ID differs")
        if d.get("source_object_key", "").strip() != candidate.get("source_object_key", "").strip():
            reasons.append("deduplication archive key differs")

    matches = [
        row for row in dryrun
        if row.get("cve_id", "").strip() == cve
        and row.get("doc_id", "").strip() == candidate.get("source_doc_id", "").strip()
        and row.get("object_key", "").strip() == candidate.get("source_object_key", "").strip()
    ]
    if not matches:
        reasons.append("no matching archived source dry-run record")
    elif any(row.get("checksum_status", "").strip() != "PASS" for row in matches):
        reasons.append("dry-run checksum status is not PASS")
    elif any(row.get("source_id", "").strip() != "redhat" for row in matches):
        reasons.append("dry-run source is not Red Hat")
    elif any(row.get("candidate_title", "").strip() != title for row in matches):
        reasons.append("dry-run source candidate differs")

    if reasons:
        return None, reasons

    async with db.conn() as conn:
        vulnerability = await conn.fetchrow(
            "SELECT * FROM public.vulnerabilities WHERE cve_id=$1", cve
        )
        raw_doc = await conn.fetchrow("""
            SELECT doc_id, source_id, url, content_sha256,
                   content_type, object_key, fetched_at
            FROM public.raw_documents
            WHERE doc_id=$1
        """, candidate["source_doc_id"].strip())
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, enabled
            FROM public.sources
            WHERE source_id='redhat'
        """)

    if vulnerability is None:
        return None, ["live vulnerability row does not exist"]
    if raw_doc is None:
        return None, ["live raw_documents metadata is missing"]
    if source is None:
        return None, ["Red Hat source registry entry is missing"]

    vulnerability = dict(vulnerability)
    raw_doc = dict(raw_doc)
    source = dict(source)

    if vulnerability.get("title", "").strip().casefold() != cve.casefold():
        return None, ["live title is no longer the CVE placeholder"]
    if raw_doc["source_id"] != "redhat":
        return None, ["live archive metadata source is not Red Hat"]
    if raw_doc["object_key"] != candidate["source_object_key"].strip():
        return None, ["live archive key differs from review file"]
    if str(source["source_class"]).lower() != "authoritative":
        return None, ["Red Hat source is not authoritative"]
    if not source["enabled"] or float(source["trust"]) < 0.90:
        return None, ["Red Hat source is disabled or trust is below 0.90"]

    raw = await asyncio.to_thread(storage.get_raw, raw_doc["object_key"])
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        raw_bytes = raw
    else:
        raw_bytes = bytes(raw)

    actual_hash = hashlib.sha256(raw_bytes).hexdigest()
    if actual_hash != raw_doc["content_sha256"]:
        return None, ["fresh archive SHA-256 verification failed"]

    try:
        archived_payload = json.loads(raw_bytes)
        parsed = [
            record for record in parse_redhat(archived_payload)
            if str(record.get("cve_id", "")).strip().upper() == cve.upper()
        ]
    except Exception as exc:
        return None, [f"archive/parser verification failed: {type(exc).__name__}"]

    if len(parsed) != 1:
        return None, [f"expected one parsed Red Hat record; found {len(parsed)}"]
    if parsed[0].get("title", "").strip() != title:
        return None, ["freshly parsed archive title differs from candidate"]

    manifest_row = {
        "cve_id": cve,
        "current_title": vulnerability.get("title", ""),
        "candidate_title": title,
        "source_id": "redhat",
        "source_class": source["source_class"],
        "source_trust": source["trust"],
        "source_doc_id": raw_doc["doc_id"],
        "source_object_key": raw_doc["object_key"],
        "source_url": raw_doc["url"],
        "source_fetched_at": raw_doc["fetched_at"],
        "content_sha256": raw_doc["content_sha256"],
        "checksum_status": "PASS",
        "parser_title_status": "PASS",
        "review_status": "TECHNICAL_PREFLIGHT_ONLY",
    }

    return {
        "manifest": manifest_row,
        "before_row": to_jsonable(vulnerability),
    }, []


async def main():
    if MANIFEST_FILE.exists() or SNAPSHOT_FILE.exists():
        raise SystemExit(
            "STOP: batch manifest or snapshot already exists. "
            "Inspect the existing files before rerunning."
        )

    norm_rows = load_csv(NORM_FILE)
    preflight_rows = load_csv(PREFLIGHT_FILE)
    dedup_rows = load_csv(DEDUP_FILE)
    dryrun_rows = load_csv(DRYRUN_FILE)

    norm = unique_map(norm_rows, "cve_id", NORM_FILE.name)
    preflight = unique_map(preflight_rows, "cve_id", PREFLIGHT_FILE.name)
    dedup = unique_map(dedup_rows, "cve_id", DEDUP_FILE.name)

    counters = Counter()
    selected = []
    before_rows = {}

    for cve in sorted(norm):
        result, reasons = await inspect_candidate(
            norm[cve], preflight, dedup, dryrun_rows
        )
        if result is None:
            counters.update(reasons)
            continue

        selected.append(result["manifest"])
        before_rows[cve] = result["before_row"]
        if len(selected) == TARGET_COUNT:
            break

    if len(selected) != TARGET_COUNT:
        print("Verified candidates found:", len(selected))
        print("Common exclusions:", dict(counters.most_common(15)))
        raise SystemExit(
            "STOP: could not verify 10 candidates. No manifest or snapshot written."
        )

    fields = list(selected[0].keys())
    with MANIFEST_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(selected)

    snapshot = {
        "purpose": "before-state snapshot for a 10-CVE Red Hat recovery preflight",
        "created_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "publication_performed": False,
        "database_rows": before_rows,
        "manifest": selected,
    }
    SNAPSHOT_FILE.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("========== VERIFIED BATCH-10 PREFLIGHT ==========")
    print("Candidates verified:", len(selected))
    print("Kafka publications: 0")
    print("Database updates: 0")
    print("Manifest:", MANIFEST_FILE)
    print("Before-state snapshot:", SNAPSHOT_FILE)
    print()
    for row in selected:
        print(
            row["cve_id"], "|", row["candidate_title"],
            "| checksum=PASS | parser=PASS"
        )
    print()
    print("TECHNICAL PREFLIGHT ONLY: candidates still require review before replay.")


if __name__ == "__main__":
    asyncio.run(main())

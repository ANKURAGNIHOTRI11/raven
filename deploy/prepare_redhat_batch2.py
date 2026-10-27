import asyncio
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from raven_common import db, storage
from parsers import parse_redhat

ROOT = Path("/workspace")
OUT = ROOT / "raven_redhat_batch2_manifest.csv"
SNAP = ROOT / "raven_redhat_batch2_before.json"

NORM = ROOT / "raven_redhat_title_normalized_review.csv"
PREFLIGHT = ROOT / "raven_redhat_title_preflight.csv"
DEDUP = ROOT / "raven_redhat_title_review_dedup.csv"
DRYRUN = ROOT / "raven_redhat_title_dryrun.csv"
BATCH1 = ROOT / "raven_redhat_batch10_manifest.csv"

LIMIT = 10
MAX_TITLE_LEN = 120
SECURITY_CUE = re.compile(
    r"\b(denial of service|dos|arbitrary|execution|injection|bypass|"
    r"privilege escalation|information disclosure|out[- ]of[- ]bounds|"
    r"use[- ]after[- ]free|buffer overflow|integer overflow|memory corruption|"
    r"traversal|authentication|authorization|cross[- ]site|xss|ssrf|xxe|"
    r"smuggling|deserialization|race condition|null pointer|command execution|"
    r"access control|sandbox escape|remote code|code execution|leak|crash|"
    r"vulnerability|improper validation|untrusted input|path traversal|"
    r"symlink|directory traversal|unsafe deserialization|certificate validation|"
    r"cryptographic|insecure|exposure|sensitive data|privilege|"
    r"signature verification)\b",
    re.IGNORECASE,
)


def read_csv(path):
    if not path.is_file():
        raise SystemExit("STOP: missing file: " + path.name)
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def unique_map(rows, filename):
    result = {}
    for row in rows:
        cve = (row.get("cve_id") or "").strip()
        if not cve or cve in result:
            raise SystemExit(
                "STOP: blank or duplicate CVE ID in " + filename + ": " + cve
            )
        result[cve] = row
    return result


def jsonable(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


async def main():
    if OUT.exists() or SNAP.exists():
        raise SystemExit(
            "STOP: batch-2 manifest or snapshot already exists. "
            "Inspect it before retrying."
        )

    norm = unique_map(read_csv(NORM), NORM.name)
    preflight = unique_map(read_csv(PREFLIGHT), PREFLIGHT.name)
    dedup = unique_map(read_csv(DEDUP), DEDUP.name)
    dryrun = read_csv(DRYRUN)
    batch1 = read_csv(BATCH1)

    excluded = {
        (r.get("cve_id") or "").strip()
        for r in batch1
    }
    excluded.discard("")
    excluded.add("CVE-2026-96658")

    async with db.conn() as conn:
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, enabled
            FROM public.sources
            WHERE source_id='redhat'
        """)

    if source is None:
        raise SystemExit("STOP: Red Hat source registry entry not found.")
    if str(source["source_class"]).lower() != "authoritative":
        raise SystemExit("STOP: Red Hat is not configured as authoritative.")
    if not source["enabled"] or float(source["trust"]) < 0.90:
        raise SystemExit("STOP: Red Hat source is disabled or trust is too low.")

    selected = []
    before_rows = {}
    rejected = Counter()

    for cve in sorted(norm):
        if cve in excluded:
            continue

        candidate = norm[cve]
        title = (candidate.get("normalized_candidate") or "").strip()

        if candidate.get("review_status") != "REVIEW_SOURCE_CANDIDATE":
            rejected["not an unchanged source candidate"] += 1
            continue
        if candidate.get("source_field", "").strip() != "bugzilla_description":
            rejected["unexpected source field"] += 1
            continue
        if (candidate.get("original_candidate") or "").strip() != title:
            rejected["candidate requires normalization"] += 1
            continue
        if not title or len(title) > MAX_TITLE_LEN:
            rejected["empty or long candidate title"] += 1
            continue
        if title.casefold() == cve.casefold():
            rejected["placeholder title"] += 1
            continue
        if not SECURITY_CUE.search(title):
            rejected["no recognizable security-impact cue"] += 1
            continue
        if candidate.get("current_title", "").strip().casefold() != cve.casefold():
            rejected["review row is not a current placeholder"] += 1
            continue

        p = preflight.get(cve)
        d = dedup.get(cve)
        if not p or not d:
            rejected["missing review row"] += 1
            continue
        if (p.get("review_flags") or "").strip():
            rejected["preflight flag present"] += 1
            continue
        if p.get("candidate_title", "").strip() != title:
            rejected["preflight title mismatch"] += 1
            continue
        if d.get("review_status") != "SINGLE_DISTINCT_CANDIDATE_REVIEW":
            rejected["conflicting or unavailable candidate"] += 1
            continue
        if d.get("distinct_candidate_count", "").strip() != "1":
            rejected["candidate is not unique"] += 1
            continue
        if d.get("candidate_title", "").strip() != title:
            rejected["deduplicated title mismatch"] += 1
            continue

        matches = [
            r for r in dryrun
            if r.get("cve_id", "").strip() == cve
            and r.get("source_id", "").strip() == "redhat"
            and r.get("doc_id", "").strip() == candidate.get("source_doc_id", "").strip()
            and r.get("object_key", "").strip() == candidate.get("source_object_key", "").strip()
            and r.get("candidate_title", "").strip() == title
            and r.get("checksum_status", "").strip() == "PASS"
        ]
        if not matches:
            rejected["no matching checksum-verified source record"] += 1
            continue

        async with db.conn() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM public.vulnerabilities WHERE cve_id=$1", cve
            )
            archive = await conn.fetchrow("""
                SELECT doc_id, source_id, url, content_sha256,
                       content_type, object_key, fetched_at
                FROM public.raw_documents
                WHERE doc_id=$1
            """, candidate["source_doc_id"].strip())

        if row is None or archive is None:
            rejected["live row or archive metadata missing"] += 1
            continue

        current = dict(row)
        archive = dict(archive)

        if current.get("title", "").strip().casefold() != cve.casefold():
            rejected["live title no longer a placeholder"] += 1
            continue
        if archive["source_id"] != "redhat":
            rejected["archive source mismatch"] += 1
            continue
        if archive["object_key"] != candidate["source_object_key"].strip():
            rejected["archive key mismatch"] += 1
            continue

        raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        if hashlib.sha256(raw).hexdigest() != archive["content_sha256"]:
            rejected["fresh archive checksum failed"] += 1
            continue

        try:
            archived = json.loads(raw)
            parsed = [
                r for r in parse_redhat(archived)
                if str(r.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception:
            rejected["archive parsing failed"] += 1
            continue

        if len(parsed) != 1 or parsed[0].get("title", "").strip() != title:
            rejected["parsed title does not match candidate"] += 1
            continue

        item = {
            "cve_id": cve,
            "current_title": current["title"],
            "candidate_title": title,
            "source_id": "redhat",
            "source_class": source["source_class"],
            "source_trust": source["trust"],
            "source_field": "bugzilla_description",
            "source_doc_id": archive["doc_id"],
            "source_object_key": archive["object_key"],
            "source_url": archive["url"],
            "source_fetched_at": archive["fetched_at"],
            "content_sha256": archive["content_sha256"],
            "checksum_status": "PASS",
            "parser_title_status": "PASS",
            "review_status": "TECHNICAL_PREFLIGHT_ONLY",
        }
        selected.append(item)
        before_rows[cve] = jsonable(current)

        if len(selected) == LIMIT:
            break

    if len(selected) != LIMIT:
        print("Verified candidates found:", len(selected))
        print("Exclusion counts:", dict(rejected.most_common(15)))
        raise SystemExit(
            "STOP: fewer than 10 candidates passed. No batch-2 manifest or "
            "snapshot was written."
        )

    snapshot = {
        "purpose": "before-state snapshot for Red Hat title recovery batch 2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "publication_performed": False,
        "database_rows": before_rows,
        "manifest": jsonable(selected),
    }

    with OUT.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(selected[0].keys()))
        writer.writeheader()
        writer.writerows(selected)

    with SNAP.open("x", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False, default=str)
        f.write("\n")

    print("========== BATCH-2 TECHNICAL PREFLIGHT ==========")
    print("Verified candidates:", len(selected))
    print("Previously considered CVEs excluded:", len(excluded))
    print("Kafka publications: 0")
    print("Vulnerability database updates: 0")
    print("Manifest:", OUT)
    print("Before-state snapshot:", SNAP)
    print("\nReview these candidate titles:")
    for i, item in enumerate(selected, 1):
        print(f"{i:02d}. {item['cve_id']} — {item['candidate_title']}")
        print("    archive checksum: PASS; parser title: PASS")
    print("\nTechnical checks only; not approval to publish.")

if __name__ == "__main__":
    asyncio.run(main())

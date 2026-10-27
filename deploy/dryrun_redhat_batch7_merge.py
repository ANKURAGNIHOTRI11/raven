import asyncio
import csv
import hashlib
import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, "/workspace/tests")

from ingest_gate_harness import N
from parsers import parse_redhat
from raven_common import db, storage
from raven_common.models import SourceClass

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch7_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch7_before.json"

PREVIOUS = [
    ROOT / "raven_redhat_batch10_manifest.csv",
    ROOT / "raven_redhat_batch2_manifest.csv",
    ROOT / "raven_redhat_batch3_manifest.csv",
    ROOT / "raven_redhat_batch4_manifest.csv",
    ROOT / "raven_redhat_batch5_manifest.csv",
    ROOT / "raven_redhat_batch6_manifest.csv",
]

PROTECTED = (
    "description",
    "published",
    "modified",
    "cvss_base",
    "cvss_vector",
    "cvss_version",
    "severity",
)


def read_csv(path):
    if not path.is_file():
        raise SystemExit(f"STOP: missing file: {path.name}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def canonical(value):
    if isinstance(value, datetime):
        return ("datetime", value.isoformat())

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return ("datetime", parsed.isoformat())
        except ValueError:
            return ("string", value)

    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        return ("number", float(value))

    return ("json", json.dumps(value, sort_keys=True, default=str))


def document_id(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


async def main():
    rows = read_csv(MANIFEST)
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before_rows = snapshot.get("database_rows", {})

    manifest = {}
    for item in rows:
        cve = item["cve_id"].strip()
        if not cve or cve in manifest:
            raise SystemExit(f"STOP: duplicate/blank CVE ID: {cve!r}")
        manifest[cve] = item

    if len(manifest) != 10 or set(manifest) != set(before_rows):
        raise SystemExit("STOP: batch-3 manifest and snapshot do not match.")

    previous_cves = {"CVE-2026-96658"}
    for path in PREVIOUS:
        for item in read_csv(path):
            cve = item.get("cve_id", "").strip()
            if cve:
                previous_cves.add(cve)

    overlap = set(manifest) & previous_cves
    if overlap:
        raise SystemExit(
            "STOP: batch-3 overlaps earlier candidates: "
            + ", ".join(sorted(overlap))
        )

    async with db.conn() as conn:
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, enabled
            FROM public.sources
            WHERE source_id='redhat'
        """)

    if source is None:
        raise SystemExit("STOP: Red Hat source entry is missing.")
    if str(source["source_class"]).lower() != "authoritative":
        raise SystemExit("STOP: Red Hat source is not authoritative.")
    if not source["enabled"] or float(source["trust"]) < 0.90:
        raise SystemExit("STOP: source disabled or trust below 0.90.")

    failures = []
    replay_ids = set()

    print("========== BATCH-7 READ-ONLY MERGE SIMULATION ==========")
    print("Candidates:", len(manifest))
    print("Kafka publications: 0")
    print("Database writes: 0\n")

    for cve in sorted(manifest):
        item = manifest[cve]
        title = item["candidate_title"].strip()

        if item.get("source_id") != "redhat":
            failures.append((cve, "manifest source is not Red Hat"))
            continue
        if item.get("checksum_status") != "PASS":
            failures.append((cve, "manifest checksum status is not PASS"))
            continue
        if item.get("parser_title_status") != "PASS":
            failures.append((cve, "manifest parser status is not PASS"))
            continue
        if not title or title.casefold() == cve.casefold() or len(title) > 120:
            failures.append((cve, "candidate title is invalid"))
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
            """, item["source_doc_id"].strip())

        if row is None or archive is None:
            failures.append((cve, "live vulnerability row or archive metadata missing"))
            continue

        existing = dict(row)
        archive = dict(archive)
        saved = before_rows[cve]

        # normalized_at is mutable pipeline metadata. Live ingestion can
        # refresh it after the snapshot without changing vulnerability content.
        # Continue comparing every other field and check protected fields below.
        differences = [
            key for key in existing
            if key != "normalized_at"
            and canonical(existing.get(key)) != canonical(saved.get(key))
        ]
        if differences:
            failures.append(
                (cve, "live row differs from snapshot: " + ", ".join(differences))
            )
            continue

        if existing.get("title", "").strip().casefold() != cve.casefold():
            failures.append((cve, "current title is no longer a placeholder"))
            continue
        if archive["source_id"] != "redhat":
            failures.append((cve, "archive source mismatch"))
            continue
        if archive["object_key"] != item["source_object_key"]:
            failures.append((cve, "archive object-key mismatch"))
            continue
        if archive["content_sha256"] != item["content_sha256"]:
            failures.append((cve, "archive checksum metadata mismatch"))
            continue

        raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        if hashlib.sha256(raw).hexdigest() != archive["content_sha256"]:
            failures.append((cve, "fresh archive checksum failed"))
            continue

        try:
            parsed = [
                record
                for record in parse_redhat(json.loads(raw))
                if str(record.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception as exc:
            failures.append((cve, f"archive parser error: {type(exc).__name__}"))
            continue

        if len(parsed) != 1 or parsed[0].get("title", "").strip() != title:
            failures.append((cve, "freshly parsed title differs from manifest"))
            continue

        record = parsed[0]
        replay_id = document_id("redhat", record)

        if replay_id in replay_ids:
            failures.append((cve, "duplicate replay document ID"))
            continue
        replay_ids.add(replay_id)

        async with db.conn() as conn:
            existing_doc = await conn.fetchrow(
                "SELECT doc_id FROM public.raw_documents WHERE doc_id=$1",
                replay_id,
            )

        if existing_doc is not None:
            failures.append(
                (cve, "replay document already registered; inspect before retry")
            )
            continue

        incoming = dict(record)
        incoming["provenance"] = [replay_id]

        merged = N.merge(
            existing,
            incoming,
            trust=float(source["trust"]),
            klass=SourceClass(source["source_class"]),
        )

        if merged.get("title") != title:
            failures.append((cve, "simulated merge failed to recover title"))
            continue

        changed = [
            field for field in PROTECTED
            if canonical(merged.get(field)) != canonical(existing.get(field))
        ]
        if changed:
            failures.append(
                (cve, "simulated merge changes protected fields: "
                 + ", ".join(changed))
            )
            continue

        print(f"PASS {cve}")
        print(f"  Proposed title: {title}")
        print("  Archive checksum: PASS")
        print("  Saved before-state: PASS")
        print("  Merge title: PASS")
        print("  Protected fields: PASS")

    print("\n========== FINAL RESULT ==========")
    if failures:
        print(f"FAIL: {len(failures)} candidate(s) need investigation.")
        for cve, reason in failures:
            print(f"  {cve}: {reason}")
        raise SystemExit(1)

    print("PASS: all 10 candidates passed the read-only merge simulation.")
    print("No Kafka messages published; no database rows changed.")


if __name__ == "__main__":
    asyncio.run(main())

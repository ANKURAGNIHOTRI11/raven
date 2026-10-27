import argparse
import asyncio
import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, "/workspace/tests")

from ingest_gate_harness import N
from parsers import parse_redhat
from raven_common import db, storage, bus, topics
from raven_common.models import RawDocument, SourceClass

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch3_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch3_before.json"
NORMALIZED = ROOT / "raven_redhat_title_normalized_review.csv"
PREFLIGHT = ROOT / "raven_redhat_title_preflight.csv"
DEDUP = ROOT / "raven_redhat_title_review_dedup.csv"
PRIOR_BATCHES = [
    ROOT / "raven_redhat_batch10_manifest.csv",
    ROOT / "raven_redhat_batch2_manifest.csv",
]
LOG = ROOT / "raven_redhat_batch3_publish.jsonl"

CONFIRM = "PUBLISH-REDHAT-BATCH3"
PROTECTED = (
    "description", "published", "modified",
    "cvss_base", "cvss_vector", "cvss_version", "severity",
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
            raise SystemExit("STOP: blank/duplicate CVE in " + filename)
        result[cve] = row
    return result


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


def append_log(event):
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()

    if args.publish and args.confirm != CONFIRM:
        raise SystemExit("STOP: publication requires --confirm " + CONFIRM)
    if args.publish and LOG.exists():
        raise SystemExit(
            "STOP: publication log already exists. Inspect it before retrying."
        )

    manifest = unique_map(read_csv(MANIFEST), MANIFEST.name)
    norm = unique_map(read_csv(NORMALIZED), NORMALIZED.name)
    preflight = unique_map(read_csv(PREFLIGHT), PREFLIGHT.name)
    dedup = unique_map(read_csv(DEDUP), DEDUP.name)
    prior_rows = [row for path in PRIOR_BATCHES for row in read_csv(path)]

    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before_rows = snapshot.get("database_rows", {})

    if len(manifest) != 10 or set(manifest) != set(before_rows):
        raise SystemExit("STOP: batch-2 manifest and snapshot do not match.")

    old_cves = {
        r.get("cve_id", "").strip()
        for r in prior_rows if r.get("cve_id", "").strip()
    }
    old_cves.add("CVE-2026-96658")

    overlap = set(manifest) & old_cves
    if overlap:
        raise SystemExit("STOP: CVE overlap with previous batch: " + ", ".join(sorted(overlap)))

    async with db.conn() as conn:
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, enabled
            FROM public.sources
            WHERE source_id='redhat'
        """)

    if source is None:
        raise SystemExit("STOP: Red Hat source is missing.")
    if str(source["source_class"]).lower() != "authoritative":
        raise SystemExit("STOP: Red Hat is not authoritative.")
    if not source["enabled"] or float(source["trust"]) < 0.90:
        raise SystemExit("STOP: Red Hat source disabled or trust below 0.90.")

    prepared = []
    seen_ids = set()

    # Complete every read-only check before any publication or metadata insert.
    for cve in sorted(manifest):
        item = manifest[cve]
        title = item["candidate_title"].strip()

        n = norm.get(cve)
        p = preflight.get(cve)
        d = dedup.get(cve)

        if not n or not p or not d:
            raise SystemExit(f"STOP: missing review row for {cve}.")
        if n.get("review_status") != "REVIEW_SOURCE_CANDIDATE":
            raise SystemExit(f"STOP: not an unchanged source candidate: {cve}.")
        if n.get("original_candidate", "").strip() != title:
            raise SystemExit(f"STOP: original source title mismatch: {cve}.")
        if n.get("normalized_candidate", "").strip() != title:
            raise SystemExit(f"STOP: normalized candidate mismatch: {cve}.")
        if p.get("review_flags", "").strip():
            raise SystemExit(f"STOP: preflight flag present for {cve}.")
        if d.get("review_status") != "SINGLE_DISTINCT_CANDIDATE_REVIEW":
            raise SystemExit(f"STOP: candidate is not unique for {cve}.")
        if d.get("distinct_candidate_count", "").strip() != "1":
            raise SystemExit(f"STOP: distinct candidate count is not one: {cve}.")
        if d.get("candidate_title", "").strip() != title:
            raise SystemExit(f"STOP: deduplicated title mismatch: {cve}.")
        if item.get("checksum_status") != "PASS":
            raise SystemExit(f"STOP: manifest checksum status is not PASS: {cve}.")
        if item.get("parser_title_status") != "PASS":
            raise SystemExit(f"STOP: manifest parser status is not PASS: {cve}.")
        if not title or title.casefold() == cve.casefold() or len(title) > 120:
            raise SystemExit(f"STOP: invalid title: {cve}.")

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
            raise SystemExit(f"STOP: live row or archive metadata missing: {cve}.")

        existing = dict(row)
        archive = dict(archive)
        saved = before_rows[cve]

        if set(existing) != set(saved) or any(
            canonical(existing.get(key)) != canonical(saved.get(key))
            for key in existing
        ):
            raise SystemExit(f"STOP: live row differs from snapshot: {cve}.")
        if existing.get("title", "").strip().casefold() != cve.casefold():
            raise SystemExit(f"STOP: title is no longer a placeholder: {cve}.")
        if archive["source_id"] != "redhat":
            raise SystemExit(f"STOP: archive source mismatch: {cve}.")
        if archive["object_key"] != item["source_object_key"]:
            raise SystemExit(f"STOP: archive object key mismatch: {cve}.")
        if archive["content_sha256"] != item["content_sha256"]:
            raise SystemExit(f"STOP: archive metadata checksum mismatch: {cve}.")

        raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        if hashlib.sha256(raw).hexdigest() != archive["content_sha256"]:
            raise SystemExit(f"STOP: fresh archive checksum failed: {cve}.")

        try:
            records = [
                rec for rec in parse_redhat(json.loads(raw))
                if str(rec.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception as exc:
            raise SystemExit(
                f"STOP: parser failed for {cve}: {type(exc).__name__}"
            ) from exc

        if len(records) != 1 or records[0].get("title", "").strip() != title:
            raise SystemExit(f"STOP: parsed title mismatch: {cve}.")

        record = records[0]
        new_id = document_id("redhat", record)

        if new_id in seen_ids:
            raise SystemExit(f"STOP: duplicate replay document ID: {cve}.")
        seen_ids.add(new_id)

        async with db.conn() as conn:
            already = await conn.fetchrow(
                "SELECT doc_id FROM public.raw_documents WHERE doc_id=$1",
                new_id,
            )
        if already is not None:
            raise SystemExit(
                f"STOP: replay document already registered for {cve}; inspect state."
            )

        incoming = dict(record)
        incoming["provenance"] = [new_id]
        merged = N.merge(
            existing, incoming,
            trust=float(source["trust"]),
            klass=SourceClass(source["source_class"]),
        )

        if merged.get("title") != title:
            raise SystemExit(f"STOP: merge no longer recovers title for {cve}.")
        for field in PROTECTED:
            if canonical(merged.get(field)) != canonical(existing.get(field)):
                raise SystemExit(
                    f"STOP: merge would change {field} for {cve}."
                )

        doc = RawDocument(
            doc_id=new_id,
            source_id="redhat",
            source_class=SourceClass(source["source_class"]),
            url=archive["url"],
            fetched_at=archive["fetched_at"],
            content_sha256=archive["content_sha256"],
            content_type=archive["content_type"] or "application/json",
            object_key=archive["object_key"],
            payload=record,
            trust=float(source["trust"]),
        )
        prepared.append((cve, title, doc))
        print(f"PASS {cve}: row, archive, merge and protected fields")

    print("\nPreflight passed:", len(prepared), "records")
    print("Mode:", "PUBLISH REQUESTED" if args.publish else "READ-ONLY PREFLIGHT")
    print("Excluded prior CVEs:", len(old_cves))

    if not args.publish:
        print("No Kafka messages published; no database rows changed.")
        return

    # Only the explicit --publish + --confirm mode reaches this section.
    with LOG.open("x", encoding="utf-8") as f:
        f.write(json.dumps({
            "event": "batch_started",
            "timestamp": datetime.now().astimezone().isoformat(),
            "cves": [cve for cve, _, _ in prepared],
        }) + "\n")
        f.flush()
        os.fsync(f.fileno())

    producer = await bus.Producer("title_recovery_batch3").start()
    try:
        for index, (cve, title, doc) in enumerate(prepared, 1):
            async with db.conn() as conn:
                status = await conn.execute("""
                    INSERT INTO public.raw_documents
                        (doc_id, source_id, url, content_sha256,
                         content_type, object_key, fetched_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7)
                    ON CONFLICT DO NOTHING
                """,
                    doc.doc_id, doc.source_id, doc.url, doc.content_sha256,
                    doc.content_type, doc.object_key, doc.fetched_at,
                )

            if status.endswith(" 0"):
                raise RuntimeError(
                    f"STOP: provenance insert was not confirmed for {cve}. "
                    "Inspect the publication log before retrying."
                )

            await producer.send(topics.RAW_DOCUMENTS, doc, key=cve)

            append_log({
                "event": "message_acknowledged",
                "index": index,
                "cve_id": cve,
                "title": title,
                "doc_id": doc.doc_id,
                "topic": topics.RAW_DOCUMENTS,
                "timestamp": datetime.now().astimezone().isoformat(),
            })
            print(f"Kafka acknowledged {index}/{len(prepared)}: {cve}")

        append_log({
            "event": "batch_complete",
            "acknowledged_count": len(prepared),
            "timestamp": datetime.now().astimezone().isoformat(),
        })
        print("\nBatch 2 publication completed.")
        print("Publication log:", LOG)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())

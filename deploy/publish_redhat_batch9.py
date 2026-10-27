import argparse
import asyncio
import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/workspace/tests")
sys.path.insert(0, "/workspace/services/crawler")

from ingest_gate_harness import N
from parsers import parse_redhat
from raven_common import bus, db, storage, topics
from raven_common.models import RawDocument, SourceClass

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch10_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch10_before.json"
PREFLIGHT = ROOT / "raven_redhat_title_preflight.csv"
DEDUP = ROOT / "raven_redhat_title_review_dedup.csv"
NORMALIZED = ROOT / "raven_redhat_title_normalized_review.csv"
LOG = ROOT / "raven_redhat_batch9_publish.jsonl"

EXCLUDE = {"CVE-2026-101725"}
CONFIRMATION = "PUBLISH-REDAH-BATCH9"

PROTECTED = (
    "description", "published", "modified",
    "cvss_base", "cvss_vector", "cvss_version", "severity",
)


def jsonable(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


def document_id(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def read_csv(path):
    if not path.is_file():
        raise SystemExit(f"STOP: required file missing: {path.name}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def unique_by_cve(rows, label):
    result = {}
    for row in rows:
        cve = row.get("cve_id", "").strip()
        if not cve or cve in result:
            raise SystemExit(f"STOP: blank/duplicate CVE in {label}: {cve!r}")
        result[cve] = row
    return result


def add_event(event):
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--publish", action="store_true",
        help="Publish the verified batch to Kafka",
    )
    parser.add_argument(
        "--confirm", default="",
        help=f"Required confirmation text: {CONFIRMATION}",
    )
    args = parser.parse_args()

    if args.publish and args.confirm != CONFIRMATION:
        raise SystemExit(
            f"STOP: publication requires --confirm {CONFIRMATION}"
        )
    if args.publish and LOG.exists():
        raise SystemExit(
            f"STOP: publication log already exists at {LOG}. "
            "Inspect it before any retry."
        )
    if not MANIFEST.is_file() or not SNAPSHOT.is_file():
        raise SystemExit("STOP: manifest or before-state snapshot is missing.")

    manifest_rows = read_csv(MANIFEST)
    manifest = unique_by_cve(manifest_rows, MANIFEST.name)
    preflight = unique_by_cve(read_csv(PREFLIGHT), PREFLIGHT.name)
    dedup = unique_by_cve(read_csv(DEDUP), DEDUP.name)
    normalized = unique_by_cve(read_csv(NORMALIZED), NORMALIZED.name)
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before_rows = snapshot.get("database_rows", {})

    candidates = [
        manifest[cve] for cve in sorted(manifest)
        if cve not in EXCLUDE
    ]
    if len(manifest) != 10 or len(candidates) != 9:
        raise SystemExit("STOP: expected 10 manifest rows and 9 eligible rows.")
    if set(before_rows) != set(manifest):
        raise SystemExit("STOP: snapshot CVE set differs from the manifest.")

    async with db.conn() as conn:
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, enabled
            FROM public.sources
            WHERE source_id='redhat'
        """)

    if source is None:
        raise SystemExit("STOP: Red Hat source registry entry is missing.")
    if str(source["source_class"]).lower() != "authoritative":
        raise SystemExit("STOP: Red Hat source is not authoritative.")
    if not source["enabled"] or float(source["trust"]) < 0.90:
        raise SystemExit("STOP: Red Hat source is disabled or trust is too low.")

    prepared = []
    seen_doc_ids = set()

    # Complete all read-only checks before opening the producer or writing metadata.
    for item in candidates:
        cve = item["cve_id"].strip()
        title = item["candidate_title"].strip()
        if item["source_id"] != "redhat":
            raise SystemExit(f"STOP: unexpected source for {cve}.")

        p = preflight.get(cve)
        d = dedup.get(cve)
        n = normalized.get(cve)
        if not p or not d or not n:
            raise SystemExit(f"STOP: missing review row for {cve}.")
        if p.get("review_flags", "").strip():
            raise SystemExit(f"STOP: preflight flag present for {cve}.")
        if d.get("review_status") != "SINGLE_DISTINCT_CANDIDATE_REVIEW":
            raise SystemExit(f"STOP: candidate is not unique for {cve}.")
        if d.get("distinct_candidate_count", "").strip() != "1":
            raise SystemExit(f"STOP: candidate count is not one for {cve}.")
        if n.get("review_status") != "REVIEW_SOURCE_CANDIDATE":
            raise SystemExit(f"STOP: candidate is not source-only for {cve}.")
        if n.get("original_candidate", "").strip() != title:
            raise SystemExit(f"STOP: candidate was normalized for {cve}.")
        if n.get("normalized_candidate", "").strip() != title:
            raise SystemExit(f"STOP: normalized title mismatch for {cve}.")
        if p.get("candidate_title", "").strip() != title:
            raise SystemExit(f"STOP: preflight title mismatch for {cve}.")
        if d.get("candidate_title", "").strip() != title:
            raise SystemExit(f"STOP: deduplicated title mismatch for {cve}.")
        if len(title) > 120 or not title or title.casefold() == cve.casefold():
            raise SystemExit(f"STOP: invalid candidate title for {cve}.")

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
            raise SystemExit(f"STOP: live row or archive metadata missing for {cve}.")

        existing = dict(row)
        archive = dict(archive)
        before = before_rows.get(cve)
        if before is None or jsonable(existing) != before:
            raise SystemExit(
                f"STOP: live row differs from the saved before-state for {cve}."
            )
        if existing.get("title", "").strip().casefold() != cve.casefold():
            raise SystemExit(f"STOP: title is no longer a placeholder for {cve}.")
        if archive["source_id"] != "redhat":
            raise SystemExit(f"STOP: archive source mismatch for {cve}.")
        if archive["object_key"] != item["source_object_key"]:
            raise SystemExit(f"STOP: archive key mismatch for {cve}.")
        if archive["content_sha256"] != item["content_sha256"]:
            raise SystemExit(f"STOP: archive checksum metadata mismatch for {cve}.")

        raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        if hashlib.sha256(raw).hexdigest() != archive["content_sha256"]:
            raise SystemExit(f"STOP: archive checksum failed for {cve}.")

        try:
            payload = json.loads(raw)
            matches = [
                rec for rec in parse_redhat(payload)
                if str(rec.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception as exc:
            raise SystemExit(
                f"STOP: parser failed for {cve}: {type(exc).__name__}"
            ) from exc

        if len(matches) != 1 or matches[0].get("title", "").strip() != title:
            raise SystemExit(f"STOP: parsed title differs from candidate for {cve}.")

        record = matches[0]
        replay_id = document_id("redhat", record)
        if replay_id in seen_doc_ids:
            raise SystemExit(f"STOP: duplicate replay document ID for {cve}.")
        seen_doc_ids.add(replay_id)

        async with db.conn() as conn:
            replay_doc = await conn.fetchrow(
                "SELECT doc_id FROM public.raw_documents WHERE doc_id=$1",
                replay_id,
            )
        if replay_doc is not None:
            raise SystemExit(
                f"STOP: replay document already exists for {cve}; inspect before retry."
            )

        incoming = dict(record)
        incoming["provenance"] = [replay_id]
        merged = N.merge(
            existing, incoming, trust=float(source["trust"]),
            klass=SourceClass(source["source_class"]),
        )
        if merged.get("title") != title:
            raise SystemExit(f"STOP: merge simulation failed for {cve}.")
        for field in PROTECTED:
            if jsonable(merged.get(field)) != jsonable(existing.get(field)):
                raise SystemExit(
                    f"STOP: merge would change protected field {field} for {cve}."
                )

        doc = RawDocument(
            doc_id=replay_id,
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

        print(f"PASS {cve}: archive, source, row, merge and protected fields")

    print("\nPreflight passed:", len(prepared), "records")
    print("Excluded:", ", ".join(sorted(EXCLUDE)))
    print("Kafka publication:", "REQUESTED" if args.publish else "NOT REQUESTED")

    if not args.publish:
        print("Preflight only. No database writes or Kafka messages.")
        return

    producer = await bus.Producer("title_recovery_batch9").start()
    try:
        # Create a durable progress log before the first metadata insertion/publication.
        with LOG.open("x", encoding="utf-8") as f:
            f.write(json.dumps({
                "event": "batch_started",
                "timestamp": datetime.now().astimezone().isoformat(),
                "cves": [cve for cve, _, _ in prepared],
            }) + "\n")
            f.flush()
            os.fsync(f.fileno())

        for index, (cve, title, doc) in enumerate(prepared, start=1):
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
                    f"STOP: provenance insert was not confirmed for {cve}; "
                    "inspect the progress log before retrying."
                )

            await producer.send(topics.RAW_DOCUMENTS, doc, key=cve)
            add_event({
                "event": "message_acknowledged",
                "index": index,
                "cve_id": cve,
                "title": title,
                "doc_id": doc.doc_id,
                "topic": topics.RAW_DOCUMENTS,
                "timestamp": datetime.now().astimezone().isoformat(),
            })
            print(f"Kafka acknowledged {index}/{len(prepared)}: {cve}")

        add_event({
            "event": "batch_complete",
            "acknowledged_count": len(prepared),
            "timestamp": datetime.now().astimezone().isoformat(),
        })
        print("\nBatch publication completed. Verify PostgreSQL before any further replay.")
        print("Publication log:", LOG)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())

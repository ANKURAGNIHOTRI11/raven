import argparse
import asyncio
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/workspace/tests")
sys.path.insert(0, "/workspace/services/crawler")

from ingest_gate_harness import N
from parsers import parse_redhat
from raven_common import bus, db, storage, topics
from raven_common.models import RawDocument, SourceClass

TARGET = "CVE-2026-96658"
SOURCE_ID = "redhat"
ARCHIVE_DOC_ID = "614a7eda9d9704c3cf55e0dfd000231f7b55dd77"
EXPECTED_OBJECT_KEY = (
    "redhat/2026/10/03/"
    "00f30504937dacbf368e7613ee50262ea49c72134214000ca059f7be6a009d3a"
)
EXPECTED_TITLE = "foreman: Safemode Bypass leading to RCE"

BACKUP = Path("/workspace/title_recovery_before_CVE-2026-96658.json")
MARKER = Path("/workspace/title_recovery_published_CVE-2026-96658.json")


def jsonable(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


def document_id(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def assert_same(actual, expected, description):
    if actual != expected:
        raise RuntimeError(f"SAFETY CHECK FAILED: {description}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the single verified RawDocument to Kafka",
    )
    args = parser.parse_args()

    if MARKER.exists():
        raise SystemExit(
            f"STOP: publish marker already exists: {MARKER}. "
            "Inspect the prior attempt before retrying."
        )

    async with db.conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM public.vulnerabilities WHERE cve_id=$1",
            TARGET,
        )
        source = await conn.fetchrow("""
            SELECT source_id, source_class, trust, url, enabled
            FROM public.sources
            WHERE source_id=$1
        """, SOURCE_ID)
        archive = await conn.fetchrow("""
            SELECT doc_id, source_id, url, content_sha256,
                   content_type, object_key, fetched_at
            FROM public.raw_documents
            WHERE doc_id=$1
        """, ARCHIVE_DOC_ID)

    if row is None:
        raise SystemExit(f"STOP: vulnerability not found: {TARGET}")
    if source is None or not source["enabled"]:
        raise SystemExit("STOP: Red Hat source is missing or disabled.")
    if archive is None:
        raise SystemExit("STOP: expected Red Hat archive metadata not found.")
    if archive["source_id"] != SOURCE_ID:
        raise SystemExit("STOP: archive source ID mismatch.")
    if archive["object_key"] != EXPECTED_OBJECT_KEY:
        raise SystemExit("STOP: archive object key does not match expected key.")
    if source["source_class"] != "authoritative":
        raise SystemExit("STOP: Red Hat is not configured as authoritative.")
    if float(source["trust"]) < 0.90:
        raise SystemExit("STOP: Red Hat trust is below the recovery threshold.")

    existing = dict(row)
    assert_same(
        existing["title"],
        TARGET,
        "live title is no longer the identifier placeholder",
    )

    raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
    if isinstance(raw, str):
        raw = raw.encode("utf-8")

    actual_hash = hashlib.sha256(raw).hexdigest()
    assert_same(
        actual_hash,
        archive["content_sha256"],
        "archive SHA-256 mismatch",
    )

    archived_payload = json.loads(raw)
    records = [
        record for record in parse_redhat(archived_payload)
        if str(record.get("cve_id", "")).strip().upper() == TARGET
    ]

    if len(records) != 1:
        raise SystemExit(
            f"STOP: expected exactly one parsed Red Hat record for {TARGET}; "
            f"found {len(records)}."
        )

    record = records[0]
    assert_same(
        record.get("title"),
        EXPECTED_TITLE,
        "parsed title differs from the reviewed candidate",
    )

    new_doc_id = document_id(SOURCE_ID, record)

    # Simulate the normalizer's merge, including its provenance assignment.
    incoming_for_merge = dict(record)
    incoming_for_merge["provenance"] = [new_doc_id]

    merged = N.merge(
        existing,
        incoming_for_merge,
        trust=float(source["trust"]),
        klass=SourceClass(source["source_class"]),
    )
    merged["cve_id"] = TARGET

    protected_fields = (
        "description",
        "published",
        "modified",
        "cvss_base",
        "cvss_vector",
        "cvss_version",
        "severity",
    )
    preservation = {
        field: merged.get(field) == existing.get(field)
        for field in protected_fields
    }

    if merged.get("title") != EXPECTED_TITLE:
        raise SystemExit("STOP: simulated merge did not recover the title.")
    if not all(preservation.values()):
        raise SystemExit(
            f"STOP: merge did not preserve protected fields: {preservation}"
        )

    async with db.conn() as conn:
        existing_doc = await conn.fetchrow("""
            SELECT source_id, content_sha256, object_key
            FROM public.raw_documents
            WHERE doc_id=$1
        """, new_doc_id)

    # The before-state file is stored on the host through /workspace.
    before_row = jsonable(existing)
    if BACKUP.exists():
        saved = json.loads(BACKUP.read_text(encoding="utf-8"))
        assert_same(
            saved.get("before_row"),
            before_row,
            "live vulnerability row differs from the saved before-state",
        )
        assert_same(
            saved.get("new_doc_id"),
            new_doc_id,
            "prepared document ID differs from the saved preflight",
        )
    else:
        if args.publish:
            raise SystemExit(
                "STOP: no before-state snapshot exists. "
                "Run the preflight without --publish first."
            )

        snapshot = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "cve_id": TARGET,
            "before_row": before_row,
            "new_doc_id": new_doc_id,
            "candidate_title": EXPECTED_TITLE,
            "archive_doc_id": ARCHIVE_DOC_ID,
            "archive_object_key": archive["object_key"],
            "archive_sha256": archive["content_sha256"],
        }
        BACKUP.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    print("========== ONE-CVE RECOVERY PREFLIGHT ==========")
    print("CVE:", TARGET)
    print("Source class:", source["source_class"])
    print("Source trust:", source["trust"])
    print("Archive checksum:", "PASS")
    print("Archive document ID:", ARCHIVE_DOC_ID)
    print("Replay document ID:", new_doc_id)
    print("Current title:", existing["title"])
    print("Proposed title:", EXPECTED_TITLE)
    print("Merged title:", merged["title"])
    print("Title would change:", merged["title"] != existing["title"])
    print("Protected fields preserved:", preservation)
    print("Replay document already registered:", existing_doc is not None)
    print("Before-state snapshot:", BACKUP)

    if existing_doc is not None:
        assert_same(
            existing_doc["source_id"], SOURCE_ID,
            "existing replay document source mismatch",
        )
        assert_same(
            existing_doc["content_sha256"], archive["content_sha256"],
            "existing replay document checksum mismatch",
        )
        assert_same(
            existing_doc["object_key"], archive["object_key"],
            "existing replay document archive key mismatch",
        )

    if not args.publish:
        print("\nPREFLIGHT ONLY: no Kafka messages published.")
        print("No vulnerability rows updated.")
        return

    doc = RawDocument(
        doc_id=new_doc_id,
        source_id=SOURCE_ID,
        source_class=SourceClass(source["source_class"]),
        url=archive["url"],
        content_sha256=archive["content_sha256"],
        content_type=archive["content_type"] or "application/json",
        object_key=archive["object_key"],
        payload=record,
        trust=float(source["trust"]),
    )

    async with db.conn() as conn:
        await conn.execute("""
            INSERT INTO public.raw_documents
                (doc_id, source_id, url, content_sha256, content_type, object_key)
            VALUES ($1,$2,$3,$4,$5,$6)
            ON CONFLICT DO NOTHING
        """,
            doc.doc_id, doc.source_id, doc.url, doc.content_sha256,
            doc.content_type, doc.object_key,
        )

    producer = await bus.Producer("title_recovery_one").start()
    try:
        await producer.send(topics.RAW_DOCUMENTS, doc, key=TARGET)
    finally:
        await producer.stop()

    marker = {
        "published_at": datetime.now(timezone.utc).isoformat(),
        "cve_id": TARGET,
        "doc_id": new_doc_id,
        "candidate_title": EXPECTED_TITLE,
        "topic": topics.RAW_DOCUMENTS,
    }
    MARKER.write_text(
        json.dumps(marker, indent=2),
        encoding="utf-8",
    )
    print("\nKafka acknowledged the single RawDocument publication.")
    print("Publish marker:", MARKER)
    print("Check the resulting database row before any wider replay.")


if __name__ == "__main__":
    asyncio.run(main())

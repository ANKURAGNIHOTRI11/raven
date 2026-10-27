import asyncio
import csv
import json
from pathlib import Path

from raven_common import db

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch5_manifest.csv"
LOG = ROOT / "raven_redhat_batch5_publish.jsonl"


async def main():
    for path in (MANIFEST, LOG):
        if not path.is_file():
            raise SystemExit(f"STOP: required file missing: {path.name}")

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        manifest_rows = list(csv.DictReader(f))

    events = [
        json.loads(line)
        for line in LOG.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    acknowledgements = [
        event for event in events
        if event.get("event") == "message_acknowledged"
    ]

    print("========== PUBLISH LOG ==========")
    print("Acknowledged messages:", len(acknowledgements))
    print("Batch-complete event:", any(
        event.get("event") == "batch_complete" for event in events
    ))
    for event in events:
        if event.get("event") in ("batch_started", "batch_complete"):
            print(event)

    doc_ids = [event["doc_id"] for event in acknowledgements if event.get("doc_id")]
    cves = [row["cve_id"].strip() for row in manifest_rows]
    expected = {
        row["cve_id"].strip(): row["candidate_title"].strip()
        for row in manifest_rows
    }

    async with db.conn() as conn:
        vuln_rows = await conn.fetch("""
            SELECT cve_id, title
            FROM public.vulnerabilities
            WHERE cve_id = ANY($1::text[])
        """, cves)

        raw_rows = await conn.fetch("""
            SELECT doc_id, source_id, object_key
            FROM public.raw_documents
            WHERE doc_id = ANY($1::text[])
        """, doc_ids)

    actual = {row["cve_id"]: row["title"] for row in vuln_rows}
    registered = {row["doc_id"] for row in raw_rows}

    print("\n========== DATABASE / PROVENANCE ==========")
    print("Vulnerability rows found:", len(actual), "of", len(cves))
    print("Replay provenance rows found:", len(registered), "of", len(doc_ids))

    for cve in cves:
        title = actual.get(cve)
        print(
            f"{cve}: title_matches_expected={title == expected[cve]}"
            f" | current_title={title!r}"
        )

    print("\n========== REPLAY DOCUMENTS ==========")
    for row in raw_rows:
        print(
            f"{row['doc_id']} | source={row['source_id']}"
            f" | object_key={row['object_key']}"
        )

    print("\nRead-only diagnostic complete. No writes or publications performed.")


if __name__ == "__main__":
    asyncio.run(main())

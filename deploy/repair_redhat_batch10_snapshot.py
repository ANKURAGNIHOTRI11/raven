import asyncio
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from raven_common import db, storage
from parsers import parse_redhat

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch10_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch10_before.json"
EXPECTED_COUNT = 10


def jsonable(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


async def main():
    if not MANIFEST.is_file():
        raise SystemExit("STOP: existing manifest is missing.")
    if SNAPSHOT.exists():
        raise SystemExit(
            "STOP: snapshot already exists. Inspect it before proceeding."
        )

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        manifest_rows = list(csv.DictReader(f))

    if len(manifest_rows) != EXPECTED_COUNT:
        raise SystemExit(
            f"STOP: expected {EXPECTED_COUNT} manifest rows; "
            f"found {len(manifest_rows)}."
        )

    cves = [r["cve_id"].strip() for r in manifest_rows]
    if not all(cves) or len(set(cves)) != EXPECTED_COUNT:
        raise SystemExit("STOP: blank or duplicate CVE IDs in manifest.")

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

    before_rows = {}

    for item in manifest_rows:
        cve = item["cve_id"].strip()
        title = item["candidate_title"].strip()
        doc_id = item["source_doc_id"].strip()
        object_key = item["source_object_key"].strip()
        expected_hash = item["content_sha256"].strip()

        if not title or title.casefold() == cve.casefold():
            raise SystemExit(f"STOP: invalid candidate title for {cve}.")
        if item["source_id"] != "redhat":
            raise SystemExit(f"STOP: unexpected source for {cve}.")
        if item["checksum_status"] != "PASS":
            raise SystemExit(f"STOP: previous checksum status failed for {cve}.")

        async with db.conn() as conn:
            vulnerability = await conn.fetchrow(
                "SELECT * FROM public.vulnerabilities WHERE cve_id=$1",
                cve,
            )
            raw_doc = await conn.fetchrow("""
                SELECT doc_id, source_id, url, content_sha256,
                       content_type, object_key, fetched_at
                FROM public.raw_documents
                WHERE doc_id=$1
            """, doc_id)

        if vulnerability is None:
            raise SystemExit(f"STOP: live vulnerability row missing for {cve}.")
        if raw_doc is None:
            raise SystemExit(f"STOP: raw document metadata missing for {cve}.")

        vulnerability = dict(vulnerability)
        raw_doc = dict(raw_doc)

        if vulnerability.get("title", "").strip().casefold() != cve.casefold():
            raise SystemExit(
                f"STOP: current title changed since manifest creation for {cve}."
            )
        if item["current_title"].strip().casefold() != cve.casefold():
            raise SystemExit(f"STOP: manifest does not record a placeholder for {cve}.")
        if raw_doc["source_id"] != "redhat":
            raise SystemExit(f"STOP: raw document source mismatch for {cve}.")
        if raw_doc["object_key"] != object_key:
            raise SystemExit(f"STOP: archive key mismatch for {cve}.")
        if raw_doc["content_sha256"] != expected_hash:
            raise SystemExit(f"STOP: archive metadata checksum mismatch for {cve}.")
        if raw_doc["url"] != item["source_url"]:
            raise SystemExit(f"STOP: source URL mismatch for {cve}.")

        raw = await asyncio.to_thread(storage.get_raw, object_key)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != expected_hash:
            raise SystemExit(f"STOP: archived payload checksum failed for {cve}.")

        try:
            payload = json.loads(raw)
            parsed = [
                record for record in parse_redhat(payload)
                if str(record.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception as exc:
            raise SystemExit(
                f"STOP: parsing archive failed for {cve}: {type(exc).__name__}"
            ) from exc

        if len(parsed) != 1:
            raise SystemExit(
                f"STOP: expected one parsed record for {cve}; found {len(parsed)}."
            )
        if parsed[0].get("title", "").strip() != title:
            raise SystemExit(f"STOP: archived candidate title differs for {cve}.")

        before_rows[cve] = jsonable(vulnerability)
        print(f"PASS {cve}: live placeholder, source metadata and archive verified")

    snapshot = {
        "purpose": "before-state snapshot for a 10-CVE Red Hat title recovery",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "publication_performed": False,
        "database_rows": before_rows,
        "manifest": jsonable(manifest_rows),
    }

    # Serialize fully before creating the file.
    serialized = json.dumps(snapshot, indent=2, ensure_ascii=False)
    with SNAPSHOT.open("x", encoding="utf-8") as f:
        f.write(serialized)
        f.write("\n")

    print("\n========== SNAPSHOT REPAIR COMPLETE ==========")
    print("Verified candidates:", len(before_rows))
    print("Existing manifest preserved:", MANIFEST)
    print("Before-state snapshot created:", SNAPSHOT)
    print("Kafka publications: 0")
    print("Database updates: 0")
    print("This is a technical preflight, not approval to replay.")


if __name__ == "__main__":
    asyncio.run(main())

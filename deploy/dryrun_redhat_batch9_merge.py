import asyncio
import csv
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/workspace/tests")

from ingest_gate_harness import N
from parsers import parse_redhat
from raven_common import db, storage
from raven_common.models import SourceClass

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch10_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch10_before.json"
SKIP = "CVE-2026-101725"

PROTECTED = (
    "description",
    "published",
    "cvss_base",
    "cvss_vector",
    "cvss_version",
    "severity",
)

def canonical(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).isoformat()
        except ValueError:
            return value
    return value

def document_id(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]

async def main():
    if not MANIFEST.is_file() or not SNAPSHOT.is_file():
        raise SystemExit("STOP: reviewed manifest or before-state snapshot is missing.")

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        manifest = list(csv.DictReader(f))

    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before_rows = snapshot.get("database_rows", {})

    candidates = [r for r in manifest if r["cve_id"] != SKIP]
    if len(candidates) != 9:
        raise SystemExit(
            f"STOP: expected 9 candidates after excluding {SKIP}; "
            f"found {len(candidates)}."
        )

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

    failed = False
    print("========== RED HAT BATCH-9 MERGE SIMULATION ==========")
    print("Excluded collector-placeholder title:", SKIP)
    print("No Kafka publication or database writes will occur.\n")

    for item in candidates:
        cve = item["cve_id"].strip()
        title = item["candidate_title"].strip()

        if cve not in before_rows:
            print("FAIL", cve, "- missing before-state snapshot row")
            failed = True
            continue

        async with db.conn() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM public.vulnerabilities WHERE cve_id=$1", cve
            )
            archive = await conn.fetchrow("""
                SELECT source_id, url, content_sha256, content_type, object_key
                FROM public.raw_documents
                WHERE doc_id=$1
            """, item["source_doc_id"].strip())

        if row is None or archive is None:
            print("FAIL", cve, "- live vulnerability or archive metadata missing")
            failed = True
            continue

        existing = dict(row)
        archive = dict(archive)
        saved = before_rows[cve]

        if existing.get("title", "").strip().casefold() != cve.casefold():
            print("FAIL", cve, "- live title is no longer the placeholder")
            failed = True
            continue

        # Ensure the current row still matches the saved pre-recovery fields.
        mismatches = [
            key for key in existing
            if canonical(existing.get(key)) != canonical(saved.get(key))
        ]
        if mismatches:
            print(
                "FAIL", cve, "- live row differs from snapshot fields:",
                ", ".join(mismatches)
            )
            failed = True
            continue

        if archive["source_id"] != "redhat":
            print("FAIL", cve, "- source is not Red Hat")
            failed = True
            continue
        if archive["object_key"] != item["source_object_key"]:
            print("FAIL", cve, "- archive object key mismatch")
            failed = True
            continue
        if archive["content_sha256"] != item["content_sha256"]:
            print("FAIL", cve, "- archive checksum metadata mismatch")
            failed = True
            continue

        raw = await asyncio.to_thread(storage.get_raw, archive["object_key"])
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = bytes(raw)

        if hashlib.sha256(raw).hexdigest() != archive["content_sha256"]:
            print("FAIL", cve, "- archive checksum verification failed")
            failed = True
            continue

        try:
            archived_payload = json.loads(raw)
            matches = [
                r for r in parse_redhat(archived_payload)
                if str(r.get("cve_id", "")).strip().upper() == cve.upper()
            ]
        except Exception as exc:
            print("FAIL", cve, "- parser error:", type(exc).__name__)
            failed = True
            continue

        if len(matches) != 1 or matches[0].get("title", "").strip() != title:
            print("FAIL", cve, "- source parser title mismatch")
            failed = True
            continue

        incoming = dict(matches[0])
        replay_doc_id = document_id("redhat", incoming)
        incoming["provenance"] = [replay_doc_id]

        merged = N.merge(
            existing,
            incoming,
            trust=float(source["trust"]),
            klass=SourceClass(source["source_class"]),
        )

        title_ok = merged.get("title") == title
        protected = {
            field: canonical(merged.get(field)) == canonical(existing.get(field))
            for field in PROTECTED
        }

        # modified may advance under the normalizer's timestamp arbitration.
        modified_changed = (
            canonical(merged.get("modified"))
            != canonical(existing.get("modified"))
        )

        print(f"{cve}:")
        print("  Proposed title:", title)
        print("  Merged title:", merged.get("title"))
        print("  Title recovery:", "PASS" if title_ok else "FAIL")
        print("  Protected fields:", protected)
        print("  Modified timestamp would change:", modified_changed)

        if not title_ok or not all(protected.values()):
            failed = True

    print("\nBATCH MERGE RESULT:", "FAIL — investigate before replay" if failed
          else "PASS — title and protected-field simulations passed")
    print("This was a simulation only; no records or Kafka messages were changed.")

asyncio.run(main())

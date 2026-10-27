import asyncio
import csv
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from raven_common import db

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch6_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch6_before.json"
PUBLISH_LOG = ROOT / "raven_redhat_batch6_publish.jsonl"

PROTECTED = (
    "description", "published", "modified",
    "cvss_base", "cvss_vector", "cvss_version", "severity",
)

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

async def main():
    for path in (MANIFEST, SNAPSHOT, PUBLISH_LOG):
        if not path.is_file():
            raise SystemExit("STOP: required file missing: " + path.name)

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    expected = {
        row["cve_id"].strip(): row["candidate_title"].strip()
        for row in rows
    }
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before = snapshot.get("database_rows", {})

    if len(expected) != 10 or set(expected) != set(before):
        raise SystemExit("STOP: manifest and snapshot do not match.")

    events = [
        json.loads(line)
        for line in PUBLISH_LOG.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    acknowledged = {
        event["cve_id"]
        for event in events
        if event.get("event") == "message_acknowledged"
    }
    if acknowledged != set(expected):
        raise SystemExit(
            "STOP: publication log acknowledgements do not match the manifest."
        )

    print("Publication log: PASS — 10 distinct CVEs acknowledged")
    live = {}
    print("Waiting up to 120 seconds for all titles to persist...")

    for attempt in range(40):
        async with db.conn() as conn:
            result = await conn.fetch(
                """
                SELECT *
                FROM public.vulnerabilities
                WHERE cve_id = ANY($1::text[])
                """,
                list(expected),
            )
        live = {row["cve_id"]: dict(row) for row in result}
        pending = [
            cve for cve, title in expected.items()
            if cve not in live or live[cve].get("title") != title
        ]
        if not pending:
            break
        if attempt % 5 == 0:
            print("Still waiting for:", ", ".join(pending))
        await asyncio.sleep(3)

    print("\n========== TITLE VERIFICATION ==========")
    title_ok = True
    for cve, title in expected.items():
        passed = cve in live and live[cve].get("title") == title
        title_ok = title_ok and passed
        print("{}: {}".format(cve, "PASS" if passed else "PENDING/FAIL"))
        if not passed:
            print("  Expected:", title)
            print("  Actual:", live.get(cve, {}).get("title"))

    print("\n========== PROTECTED FIELD VERIFICATION ==========")
    fields_ok = True
    for cve in expected:
        if cve not in live:
            print(cve + ": FAIL — row missing")
            fields_ok = False
            continue
        changed = [
            field for field in PROTECTED
            if canonical(live[cve].get(field))
            != canonical(before[cve].get(field))
        ]
        passed = not changed
        fields_ok = fields_ok and passed
        print("{}: {}".format(
            cve, "PASS" if passed else "CHANGED — " + ", ".join(changed)
        ))

    overall = title_ok and fields_ok
    print("\n========== FINAL RESULT ==========")
    print("Titles:", "PASS" if title_ok else "NOT COMPLETE")
    print("Protected fields:", "PASS" if fields_ok else "INVESTIGATE")
    print("OVERALL:", "PASS" if overall else "NEEDS INVESTIGATION")
    print("Read-only verification; no Kafka messages or database rows changed.")

if __name__ == "__main__":
    asyncio.run(main())

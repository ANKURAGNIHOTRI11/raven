import asyncio
import csv
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from raven_common import db

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch2_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch2_before.json"

PROTECTED = (
    "description",
    "published",
    "modified",
    "cvss_base",
    "cvss_vector",
    "cvss_version",
    "severity",
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
    if not MANIFEST.is_file() or not SNAPSHOT.is_file():
        raise SystemExit("STOP: batch-2 manifest or snapshot is missing.")

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    expected = {
        row["cve_id"].strip(): row["candidate_title"].strip()
        for row in rows
    }
    before = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["database_rows"]

    if len(expected) != 10 or set(expected) != set(before):
        raise SystemExit("STOP: manifest and snapshot CVE sets do not match.")

    live = {}
    print("Waiting up to 120 seconds for all 10 titles to persist...")

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
    title_pass = True

    for cve, title in expected.items():
        actual = live.get(cve, {}).get("title")
        ok = actual == title
        title_pass = title_pass and ok
        print("{}: {}".format(cve, "PASS" if ok else "PENDING/FAIL"))
        if not ok:
            print("  Expected:", title)
            print("  Actual:  ", actual)

    print("\n========== PROTECTED FIELD VERIFICATION ==========")
    protected_pass = True

    for cve in expected:
        if cve not in live:
            print("{}: FAIL — database row missing".format(cve))
            protected_pass = False
            continue

        changed = [
            field for field in PROTECTED
            if canonical(live[cve].get(field))
            != canonical(before[cve].get(field))
        ]

        ok = not changed
        protected_pass = protected_pass and ok
        print(
            "{}: {}".format(
                cve,
                "PASS" if ok else "CHANGED — " + ", ".join(changed),
            )
        )

    print("\n========== FINAL RESULT ==========")
    print("Titles:", "PASS" if title_pass else "NOT COMPLETE")
    print("Protected fields:", "PASS" if protected_pass else "INVESTIGATE")
    overall = title_pass and protected_pass
    print("OVERALL:", "PASS" if overall else "NEEDS INVESTIGATION")
    print("Read-only check: no publication or database changes made.")


if __name__ == "__main__":
    asyncio.run(main())

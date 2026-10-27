import asyncio
import csv
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from raven_common import db

ROOT = Path("/workspace")
MANIFEST = ROOT / "raven_redhat_batch10_manifest.csv"
SNAPSHOT = ROOT / "raven_redhat_batch10_before.json"
EXCLUDED = {"CVE-2026-101725"}

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

    return ("other", value)


async def main():
    for path in (MANIFEST, SNAPSHOT):
        if not path.is_file():
            raise SystemExit("STOP: required file is missing: " + path.name)

    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    manifest = {
        row["cve_id"].strip(): row["candidate_title"].strip()
        for row in rows
        if row["cve_id"].strip() not in EXCLUDED
    }

    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    before = snapshot.get("database_rows", {})

    if len(manifest) != 9:
        raise SystemExit("STOP: expected nine eligible manifest entries.")

    if not set(manifest).issubset(before):
        raise SystemExit("STOP: manifest CVEs are missing from the snapshot.")

    live = {}
    print("Waiting up to 120 seconds for all nine titles to persist...")

    for attempt in range(40):
        async with db.conn() as conn:
            result = await conn.fetch(
                """
                SELECT *
                FROM public.vulnerabilities
                WHERE cve_id = ANY($1::text[])
                """,
                list(manifest),
            )

        live = {row["cve_id"]: dict(row) for row in result}
        pending = [
            cve for cve, title in manifest.items()
            if cve not in live or live[cve].get("title") != title
        ]

        if not pending:
            break

        if attempt % 5 == 0:
            print("Titles still pending:", ", ".join(pending))

        await asyncio.sleep(3)

    print("\n========== TITLE VERIFICATION ==========")
    title_pass = True

    for cve, expected in manifest.items():
        actual = live.get(cve, {}).get("title")
        ok = actual == expected
        title_pass = title_pass and ok

        print("{}: {}".format(cve, "PASS" if ok else "PENDING/FAIL"))

        if not ok:
            print("  Expected:", expected)
            print("  Actual:  ", actual)

    print("\n========== PROTECTED FIELD VERIFICATION ==========")
    protected_pass = True

    for cve in manifest:
        if cve not in live:
            print("{}: FAIL — row missing".format(cve))
            protected_pass = False
            continue

        mismatches = []

        for field in PROTECTED:
            current_value = live[cve].get(field)
            original_value = before[cve].get(field)

            if canonical(current_value) != canonical(original_value):
                mismatches.append(field)

        ok = not mismatches
        protected_pass = protected_pass and ok

        if ok:
            print("{}: PASS".format(cve))
        else:
            print("{}: CHANGED — {}".format(cve, ", ".join(mismatches)))

    print("\n========== FINAL RESULT ==========")
    print("Titles:", "PASS" if title_pass else "NOT COMPLETE")
    print("Protected fields:", "PASS" if protected_pass else "INVESTIGATE")

    overall = title_pass and protected_pass
    print("OVERALL:", "PASS" if overall else "NEEDS INVESTIGATION")
    print("Read-only verification completed; no messages were published.")


if __name__ == "__main__":
    asyncio.run(main())

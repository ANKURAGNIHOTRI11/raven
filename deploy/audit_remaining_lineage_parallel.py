import asyncio
import hashlib
import json
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import asyncpg
from raven_common import storage
from parsers import PARSERS

WORKERS = 20
_UNMATCHED_KEYS = set()


def doc_id_for(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def scan_archive(meta):
    """Worker: inspect one archive and return only recoverable missing IDs."""
    try:
        raw = storage.get_raw(meta["object_key"])

        if hashlib.sha256(raw).hexdigest() != meta["content_sha256"]:
            raise RuntimeError("Archive checksum mismatch")

        mode, parser = PARSERS[meta["parser"]]
        payload = json.loads(raw) if mode == "json" else raw
        records = parser(payload)

        matches = {}
        for rec in records:
            cve_id = rec.get("cve_id")
            if not cve_id:
                continue

            did = doc_id_for(meta["source_id"], rec)
            if (cve_id, did) not in _UNMATCHED_KEYS:
                continue

            matches.setdefault(did, (
                cve_id,
                did,
                meta["source_id"],
                meta["url"],
                meta["content_sha256"],
                meta["content_type"] or "application/octet-stream",
                meta["object_key"],
                meta["fetched_at"],
            ))

        return {
            "source_id": meta["source_id"],
            "object_key": meta["object_key"],
            "parsed": len(records),
            "matches": list(matches.values()),
            "error": None,
        }

    except Exception as exc:
        return {
            "source_id": meta.get("source_id", "?"),
            "object_key": meta.get("object_key", "?"),
            "parsed": 0,
            "matches": [],
            "error": str(exc)[:300],
        }


async def load_inputs():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])
    try:
        await conn.execute("SET statement_timeout = '10min'")

        print("Loading unresolved provenance references...", flush=True)
        missing = await conn.fetch("""
            SELECT DISTINCT v.cve_id, p.ref AS doc_id
            FROM public.vulnerabilities v
            CROSS JOIN LATERAL unnest(v.provenance) AS p(ref)
            LEFT JOIN public.raw_documents rd
                ON rd.doc_id = p.ref
            WHERE rd.doc_id IS NULL
        """)

        unmatched = {(r["cve_id"], r["doc_id"]) for r in missing}

        archives = await conn.fetch("""
            SELECT
                rd.source_id,
                rd.url,
                rd.content_sha256,
                rd.content_type,
                rd.object_key,
                min(rd.fetched_at) AS fetched_at,
                s.parser
            FROM public.raw_documents rd
            JOIN public.sources s USING (source_id)
            WHERE rd.source_id <> 'epss'
              AND rd.object_key IS NOT NULL
              AND rd.object_key <> ''
            GROUP BY
                rd.source_id, rd.url, rd.content_sha256,
                rd.content_type, rd.object_key, s.parser
            ORDER BY rd.source_id, min(rd.fetched_at)
        """)

        return unmatched, [dict(r) for r in archives]

    finally:
        await conn.close()


async def verify_projection(candidates):
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])
    try:
        await conn.execute("SET statement_timeout = '10min'")

        await conn.execute("""
            CREATE TEMP TABLE lineage_recovery_candidates (
                cve_id text NOT NULL,
                doc_id text PRIMARY KEY
            ) ON COMMIT PRESERVE ROWS
        """)

        if candidates:
            await conn.copy_records_to_table(
                "lineage_recovery_candidates",
                records=[(x[0], x[1]) for x in candidates.values()],
                columns=["cve_id", "doc_id"],
            )

        projected = await conn.fetchrow("""
            SELECT
                count(*) AS candidate_ids,
                count(*) FILTER (
                    WHERE rd.doc_id IS NULL
                ) AS candidates_still_missing
            FROM lineage_recovery_candidates c
            LEFT JOIN public.raw_documents rd
                ON rd.doc_id = c.doc_id
        """)

        coverage = await conn.fetchrow("""
            WITH refs AS MATERIALIZED (
                SELECT DISTINCT p.ref
                FROM public.vulnerabilities v
                CROSS JOIN LATERAL unnest(v.provenance) AS p(ref)
            )
            SELECT
                count(*) AS total_refs,
                count(*) FILTER (
                    WHERE rd.doc_id IS NOT NULL
                ) AS matched_refs,
                count(*) FILTER (
                    WHERE rd.doc_id IS NULL
                ) AS unmatched_refs
            FROM refs r
            LEFT JOIN public.raw_documents rd
                ON rd.doc_id = r.ref
        """)

        return dict(projected), dict(coverage)

    finally:
        await conn.close()


def main():
    global _UNMATCHED_KEYS

    started = time.monotonic()
    unmatched, archives = asyncio.run(load_inputs())

    _UNMATCHED_KEYS = unmatched

    print("\n========== PARALLEL ARCHIVE AUDIT ==========")
    print("Unresolved (CVE, document ID) pairs:", len(unmatched))
    print("Non-EPSS archived objects:", len(archives))
    print("Worker processes:", min(WORKERS, max(1, len(archives))))
    print("Permanent database writes: NONE")
    print("Checksum verification: enabled")

    candidates = {}
    errors = []
    parsed_total = 0
    completed = 0
    by_source = {}

    if archives:
        with ProcessPoolExecutor(
            max_workers=min(WORKERS, len(archives)),
            mp_context=multiprocessing.get_context("fork"),
        ) as pool:
            futures = {
                pool.submit(scan_archive, meta): meta
                for meta in archives
            }

            for future in as_completed(futures):
                result = future.result()
                completed += 1
                parsed_total += result["parsed"]

                if result["error"]:
                    errors.append({
                        "source_id": result["source_id"],
                        "object_key": result["object_key"],
                        "error": result["error"],
                    })
                else:
                    for item in result["matches"]:
                        did = item[1]
                        previous = candidates.get(did)

                        # If an item appears in several archives, retain
                        # the earliest archive as the restoration candidate.
                        if previous is None or item[7] < previous[7]:
                            candidates[did] = item

                    if result["matches"]:
                        sid = result["source_id"]
                        by_source.setdefault(sid, set()).update(
                            x[1] for x in result["matches"]
                        )

                if completed % 100 == 0 or completed == len(archives):
                    print(
                        f"Scanned {completed}/{len(archives)} archives; "
                        f"distinct recovery candidates={len(candidates)}; "
                        f"errors={len(errors)}",
                        flush=True,
                    )

    projected, coverage = asyncio.run(verify_projection(candidates))

    print("\n========== RECOVERY CANDIDATES BY SOURCE ==========")
    for sid, ids in sorted(
        by_source.items(),
        key=lambda entry: len(entry[1]),
        reverse=True,
    ):
        print(f"{sid}: {len(ids)} distinct IDs")

    print("\n========== DRY-RUN SUMMARY ==========")
    print("Archives scanned:", completed)
    print("Successfully parsed records:", parsed_total)
    print("Archives with errors:", len(errors))
    print("Distinct candidates found:", len(candidates))
    print("Candidates still missing:", projected["candidates_still_missing"])

    print("\nCurrent coverage:")
    for key, value in coverage.items():
        print(f"{key}: {value}")

    total = coverage["total_refs"] or 1
    projected_matched = (
        coverage["matched_refs"] + projected["candidates_still_missing"]
    )
    print(
        "Projected coverage after candidate recovery: "
        f"{100 * projected_matched / total:.4f}%"
    )
    print(f"Elapsed seconds: {time.monotonic() - started:.2f}")

    if errors:
        print("\n========== ARCHIVE ERRORS (FIRST 20) ==========")
        for err in errors[:20]:
            print(err)

    print("\nPASS: dry-run completed; permanent data unchanged")


if __name__ == "__main__":
    main()

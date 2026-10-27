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
BATCH_SIZE = 5000
UNMATCHED = set()


def doc_id_for(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def scan_archive(meta):
    """Reconstruct only unresolved provenance IDs from one archived object."""
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

            if (cve_id, did) not in UNMATCHED:
                continue

            candidate = (
                cve_id,
                did,
                meta["source_id"],
                meta["url"],
                meta["content_sha256"],
                meta["content_type"] or "application/octet-stream",
                meta["object_key"],
                meta["fetched_at"],
            )

            previous = matches.get(did)
            if previous is None or candidate[7] < previous[7]:
                matches[did] = candidate

        return {
            "object_key": meta["object_key"],
            "source_id": meta["source_id"],
            "parsed": len(records),
            "matches": list(matches.values()),
            "error": None,
        }

    except Exception as exc:
        return {
            "object_key": meta["object_key"],
            "source_id": meta["source_id"],
            "parsed": 0,
            "matches": [],
            "error": str(exc)[:300],
        }


async def load_inputs():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])
    try:
        await conn.execute("SET statement_timeout = '10min'")

        unmatched_rows = await conn.fetch("""
            SELECT DISTINCT v.cve_id, p.ref AS doc_id
            FROM public.vulnerabilities v
            CROSS JOIN LATERAL unnest(v.provenance) AS p(ref)
            LEFT JOIN public.raw_documents rd ON rd.doc_id = p.ref
            WHERE rd.doc_id IS NULL
        """)

        unmatched = {
            (row["cve_id"], row["doc_id"])
            for row in unmatched_rows
        }

        archives = await conn.fetch("""
            SELECT
                rd.source_id, rd.url, rd.content_sha256,
                rd.content_type, rd.object_key,
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

        counts = await conn.fetchrow("""
            SELECT
                (SELECT count(*) FROM public.raw_documents)
                    AS raw_documents,
                (SELECT count(*) FROM public.vulnerabilities)
                    AS vulnerabilities,
                (SELECT count(*) FROM public.vulnerability_versions)
                    AS vulnerability_versions
        """)

        return unmatched, [dict(r) for r in archives], dict(counts)

    finally:
        await conn.close()


async def persist_candidates(candidates, baseline):
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])

    try:
        await conn.execute("SET statement_timeout = '10min'")

        await conn.execute("""
            CREATE TEMP TABLE lineage_recovery_stage (
                seq bigint PRIMARY KEY,
                cve_id text NOT NULL,
                doc_id text NOT NULL UNIQUE,
                source_id text NOT NULL,
                url text,
                content_sha256 text,
                content_type text,
                object_key text NOT NULL,
                fetched_at timestamptz NOT NULL
            ) ON COMMIT PRESERVE ROWS
        """)

        ordered = sorted(
            candidates.values(),
            key=lambda item: (item[7], item[1]),
        )

        stage_rows = [
            (i, *item)
            for i, item in enumerate(ordered, start=1)
        ]

        await conn.copy_records_to_table(
            "lineage_recovery_stage",
            records=stage_rows,
            columns=[
                "seq", "cve_id", "doc_id", "source_id", "url",
                "content_sha256", "content_type", "object_key",
                "fetched_at",
            ],
        )

        # Reject stale candidates that are no longer referenced or already
        # registered. Reconfirm eligibility immediately before each batch.
        eligible = await conn.fetchval("""
            SELECT count(*)
            FROM lineage_recovery_stage s
            WHERE EXISTS (
                SELECT 1
                FROM public.vulnerabilities v
                WHERE v.cve_id = s.cve_id
                  AND s.doc_id = ANY(v.provenance)
            )
              AND NOT EXISTS (
                SELECT 1
                FROM public.raw_documents rd
                WHERE rd.doc_id = s.doc_id
            )
        """)

        print("Unique candidates staged:", len(ordered), flush=True)
        print("Still eligible for insertion:", eligible, flush=True)

        inserted_total = 0

        for start in range(1, len(ordered) + 1, BATCH_SIZE):
            end = min(start + BATCH_SIZE, len(ordered) + 1)

            async with conn.transaction():
                status = await conn.execute("""
                    INSERT INTO public.raw_documents (
                        doc_id, source_id, url, content_sha256,
                        content_type, object_key, fetched_at
                    )
                    SELECT
                        s.doc_id, s.source_id, s.url, s.content_sha256,
                        s.content_type, s.object_key, s.fetched_at
                    FROM lineage_recovery_stage s
                    WHERE s.seq >= $1
                      AND s.seq < $2
                      AND EXISTS (
                          SELECT 1
                          FROM public.vulnerabilities v
                          WHERE v.cve_id = s.cve_id
                            AND s.doc_id = ANY(v.provenance)
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM public.raw_documents rd
                          WHERE rd.doc_id = s.doc_id
                      )
                    ON CONFLICT (doc_id) DO NOTHING
                """, start, end)

            inserted = int(status.split()[-1])
            inserted_total += inserted

            print(
                f"Batch ending at {end - 1}/{len(ordered)}; "
                f"inserted this batch={inserted}; "
                f"total inserted={inserted_total}",
                flush=True,
            )

        remaining = await conn.fetchval("""
            SELECT count(*)
            FROM lineage_recovery_stage s
            WHERE NOT EXISTS (
                SELECT 1
                FROM public.raw_documents rd
                WHERE rd.doc_id = s.doc_id
            )
        """)

        after = await conn.fetchrow("""
            SELECT
                (SELECT count(*) FROM public.raw_documents)
                    AS raw_documents,
                (SELECT count(*) FROM public.vulnerabilities)
                    AS vulnerabilities,
                (SELECT count(*) FROM public.vulnerability_versions)
                    AS vulnerability_versions
        """)

        print("\n========== RECOVERY SUMMARY ==========")
        print("Candidate IDs:", len(ordered))
        print("Rows inserted by this run:", inserted_total)
        print("Candidate IDs still missing:", remaining)
        print("Counts before:", baseline)
        print("Counts after:", dict(after))

        print(
            "Vulnerability row-count delta:",
            after["vulnerabilities"] - baseline["vulnerabilities"],
        )
        print(
            "History row-count delta:",
            after["vulnerability_versions"]
            - baseline["vulnerability_versions"],
        )

        if remaining:
            raise RuntimeError(
                f"{remaining} candidates remain missing; rerun is safe"
            )

        print(
            "PASS: all staged candidate IDs now exist",
            flush=True,
        )

    finally:
        await conn.close()


def main():
    started = time.monotonic()

    unmatched, archives, baseline = asyncio.run(load_inputs())
    global UNMATCHED
    UNMATCHED = unmatched

    print("========== PARALLEL RECOVERY ==========")
    print("Unresolved (CVE, document ID) pairs:", len(unmatched))
    print("Archived objects to scan:", len(archives))
    print("Worker processes:", min(WORKERS, len(archives)))
    print("Batch size:", BATCH_SIZE)
    print("Baseline counts:", baseline)

    candidates = {}
    errors = []
    by_source = {}

    # Archive scan is parallel; all database writes remain batched
    # through one coordinator connection.
    with ProcessPoolExecutor(
        max_workers=min(WORKERS, len(archives)),
        mp_context=multiprocessing.get_context("fork"),
    ) as pool:
        futures = {
            pool.submit(scan_archive, meta): meta
            for meta in archives
        }

        for number, future in enumerate(as_completed(futures), start=1):
            result = future.result()

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
                    if previous is None or item[7] < previous[7]:
                        candidates[did] = item

                    by_source.setdefault(item[2], set()).add(did)

            if number % 100 == 0 or number == len(archives):
                print(
                    f"Scanned {number}/{len(archives)}; "
                    f"unique candidates={len(candidates)}; "
                    f"errors={len(errors)}",
                    flush=True,
                )

    # Fail closed: do not start permanent insertion if any archive could not
    # be validated and parsed.
    if errors:
        print("Archive errors:", errors[:30], flush=True)
        raise SystemExit(
            "Recovery aborted before writing because some archives failed."
        )

    print("\n========== CANDIDATES BY SOURCE ==========")
    for source, ids in sorted(
        by_source.items(), key=lambda pair: len(pair[1]), reverse=True
    ):
        print(f"{source}: {len(ids)}")

    asyncio.run(persist_candidates(candidates, baseline))

    print(
        "Elapsed seconds:",
        round(time.monotonic() - started, 2),
        flush=True,
    )


if __name__ == "__main__":
    main()

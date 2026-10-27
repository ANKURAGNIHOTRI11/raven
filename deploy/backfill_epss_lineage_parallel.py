import asyncio
import csv
import gzip
import hashlib
import io
import json
import os
import time
import multiprocessing

from concurrent.futures import ProcessPoolExecutor, as_completed

import asyncpg
from raven_common import storage

BATCH_SIZE = int(os.getenv("RAVEN_EPSS_BATCH_SIZE", "5000"))
MAX_WORKERS = min(
    20, max(1, int(os.getenv("RAVEN_EPSS_WORKERS", "20")))
)
SOURCE_ID = "epss"


def doc_id_for(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def iter_epss_records(raw):
    """Stream EPSS CSV rows without materializing the full parsed dataset."""
    if raw[:2] == b"\x1f\x8b":
        binary = gzip.GzipFile(
            fileobj=io.BytesIO(raw), mode="rb"
        )
    else:
        binary = io.BytesIO(raw)

    text = io.TextIOWrapper(
        binary, encoding="utf-8", errors="replace", newline=""
    )

    try:
        def data_lines():
            for line in text:
                clean = line.rstrip("\r\n")
                if clean and not clean.startswith("#"):
                    yield line

        for row in csv.DictReader(data_lines()):
            cve_id = (row.get("cve") or "").strip()

            if not cve_id.startswith("CVE-"):
                continue

            yield {
                "cve_id": cve_id,
                "epss_score": float(row.get("epss") or 0.0),
                "epss_percentile": float(
                    row.get("percentile") or 0.0
                ),
            }
    finally:
        text.close()


async def process_snapshot(meta):
    started = time.monotonic()
    conn = await asyncpg.connect(
        os.environ["RAVEN_PG_DSN"],
        command_timeout=300,
    )

    try:
        await conn.execute("SET statement_timeout = '5min'")

        await conn.execute("""
            CREATE TEMP TABLE epss_lineage_stage (
                cve_id text NOT NULL,
                doc_id text PRIMARY KEY
            ) ON COMMIT PRESERVE ROWS
        """)

        # Read the archived object and verify its original checksum.
        raw = await asyncio.to_thread(
            storage.get_raw, meta["object_key"]
        )

        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != meta["content_sha256"]:
            raise RuntimeError(
                f"Checksum mismatch: {meta['object_key']}"
            )

        batch = {}
        parsed_count = 0
        inserted_count = 0
        batch_count = 0

        async def flush_batch():
            nonlocal batch, inserted_count, batch_count

            if not batch:
                return

            staged = list(batch.values())

            async with conn.transaction():
                await conn.execute(
                    "TRUNCATE pg_temp.epss_lineage_stage"
                )

                await conn.copy_records_to_table(
                    "epss_lineage_stage",
                    records=staged,
                    columns=["cve_id", "doc_id"],
                )

                status = await conn.execute("""
                    INSERT INTO public.raw_documents (
                        doc_id, source_id, url, content_sha256,
                        content_type, object_key, fetched_at
                    )
                    SELECT
                        s.doc_id, $1, $2, $3, $4, $5, $6
                    FROM pg_temp.epss_lineage_stage s
                    WHERE EXISTS (
                        SELECT 1
                        FROM public.vulnerabilities v
                        WHERE v.cve_id = s.cve_id
                          AND s.doc_id = ANY(v.provenance)
                    )
                    ON CONFLICT (doc_id) DO NOTHING
                """,
                    meta["source_id"],
                    meta["url"],
                    meta["content_sha256"],
                    meta["content_type"] or "application/octet-stream",
                    meta["object_key"],
                    meta["fetched_at"],
                )

            inserted_count += int(status.split()[-1])
            batch_count += 1
            batch.clear()

            if batch_count % 10 == 0:
                print(
                    f"[{meta['object_key'].split('/')[-1][:12]}] "
                    f"parsed={parsed_count} "
                    f"inserted={inserted_count}",
                    flush=True,
                )

        for record in iter_epss_records(raw):
            parsed_count += 1

            doc_id = doc_id_for(SOURCE_ID, record)
            batch.setdefault(
                doc_id, (record["cve_id"], doc_id)
            )

            if len(batch) >= BATCH_SIZE:
                await flush_batch()

        await flush_batch()

        return {
            "object_key": meta["object_key"],
            "fetched_at": str(meta["fetched_at"]),
            "parsed_records": parsed_count,
            "new_rows_inserted": inserted_count,
            "batches_committed": batch_count,
            "elapsed_seconds": round(
                time.monotonic() - started, 2
            ),
        }

    finally:
        await conn.close()


def process_snapshot_worker(meta):
    # Each process has its own event loop and database connection.
    return asyncio.run(process_snapshot(meta))


async def load_snapshots():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])

    try:
        rows = await conn.fetch("""
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
            WHERE rd.source_id = 'epss'
              AND rd.object_key IS NOT NULL
              AND rd.object_key <> ''
            GROUP BY
                rd.source_id, rd.url, rd.content_sha256,
                rd.content_type, rd.object_key, s.parser
            ORDER BY min(rd.fetched_at)
        """)

        return [dict(row) for row in rows]

    finally:
        await conn.close()


async def get_db_counts():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])

    try:
        row = await conn.fetchrow("""
            SELECT
                (SELECT count(*) FROM public.raw_documents)
                    AS raw_documents,
                (SELECT count(*) FROM public.vulnerabilities)
                    AS vulnerabilities,
                (SELECT count(*) FROM public.vulnerability_versions)
                    AS vulnerability_versions
        """)
        return dict(row)

    finally:
        await conn.close()


def main():
    snapshots = asyncio.run(load_snapshots())

    if not snapshots:
        raise RuntimeError("No archived EPSS snapshots found")

    workers = min(MAX_WORKERS, len(snapshots))

    print("========== PARALLEL EPSS BACKFILL ==========", flush=True)
    print("Snapshots:", len(snapshots), flush=True)
    print("Worker processes:", workers, flush=True)
    print("Batch size:", BATCH_SIZE, flush=True)
    print("Checksum verification: enabled", flush=True)
    print("Vulnerability provenance filter: enabled", flush=True)
    print("Idempotent insert: ON CONFLICT (doc_id) DO NOTHING",
          flush=True)

    before = asyncio.run(get_db_counts())
    print("Counts before:", before, flush=True)

    results = []
    failures = []

    # Linux fork allows this script to be executed over stdin
    # by docker compose exec while keeping worker functions available.
    context = multiprocessing.get_context("fork")

    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=context,
    ) as pool:
        future_map = {
            pool.submit(process_snapshot_worker, meta): meta
            for meta in snapshots
        }

        for future in as_completed(future_map):
            meta = future_map[future]

            try:
                result = future.result()
                results.append(result)
                print("SNAPSHOT COMPLETE:", result, flush=True)

            except Exception as exc:
                failures.append({
                    "object_key": meta["object_key"],
                    "error": str(exc),
                })
                print(
                    "SNAPSHOT FAILED:",
                    failures[-1],
                    flush=True,
                )

    after = asyncio.run(get_db_counts())

    print("\n========== FINAL SUMMARY ==========", flush=True)
    print("Snapshots discovered:", len(snapshots), flush=True)
    print("Snapshots succeeded:", len(results), flush=True)
    print("Snapshots failed:", len(failures), flush=True)
    print(
        "Parsed records:",
        sum(r["parsed_records"] for r in results),
        flush=True,
    )
    print(
        "New rows inserted:",
        sum(r["new_rows_inserted"] for r in results),
        flush=True,
    )
    print(
        "Batches committed:",
        sum(r["batches_committed"] for r in results),
        flush=True,
    )
    print("Counts before:", before, flush=True)
    print("Counts after:", after, flush=True)

    if failures:
        print("FAILED OBJECTS:", failures, flush=True)
        raise SystemExit(
            "Backfill incomplete. Fix the reported issue and rerun; "
            "committed rows will be skipped safely."
        )

    print(
        "PASS: all archived EPSS snapshots processed",
        flush=True,
    )


if __name__ == "__main__":
    main()

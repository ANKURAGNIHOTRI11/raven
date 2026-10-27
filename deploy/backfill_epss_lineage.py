import asyncio
import hashlib
import json
import os
import time
import asyncpg

from raven_common import storage
from parsers import PARSERS

BATCH_SIZE = 10_000


def doc_id_for(source_id, payload):
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


async def main():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])
    started = time.monotonic()

    try:
        await conn.execute("SET statement_timeout = '15min'")

        before_vulns = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerabilities"
        )
        before_history = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerability_versions"
        )

        snapshots = await conn.fetch("""
            SELECT rd.source_id, rd.url, rd.content_sha256,
                   rd.content_type, rd.object_key,
                   min(rd.fetched_at) AS fetched_at,
                   s.parser
            FROM public.raw_documents rd
            JOIN public.sources s USING (source_id)
            WHERE rd.source_id = 'epss'
              AND rd.object_key IS NOT NULL
              AND rd.object_key <> ''
            GROUP BY rd.source_id, rd.url, rd.content_sha256,
                     rd.content_type, rd.object_key, s.parser
            ORDER BY min(rd.fetched_at)
        """)

        if not snapshots:
            raise RuntimeError("No archived EPSS snapshots found")

        await conn.execute("""
            CREATE TEMP TABLE IF NOT EXISTS epss_lineage_stage (
                seq bigserial PRIMARY KEY,
                cve_id text NOT NULL,
                doc_id text NOT NULL UNIQUE
            ) ON COMMIT PRESERVE ROWS
        """)

        inserted_total = 0
        eligible_total = 0
        archive_records = 0

        for number, meta in enumerate(snapshots, start=1):
            raw = await asyncio.to_thread(
                storage.get_raw, meta["object_key"]
            )

            if hashlib.sha256(raw).hexdigest() != meta["content_sha256"]:
                raise RuntimeError(
                    f"Checksum mismatch: {meta['object_key']}"
                )

            mode, parser = PARSERS[meta["parser"]]
            payload = json.loads(raw) if mode == "json" else raw
            records = parser(payload)

            await conn.execute(
                "TRUNCATE epss_lineage_stage RESTART IDENTITY"
            )

            seen = set()
            buffer = []

            for rec in records:
                cve_id = rec.get("cve_id")
                if not cve_id:
                    continue

                doc_id = doc_id_for(meta["source_id"], rec)
                if doc_id in seen:
                    continue

                seen.add(doc_id)
                buffer.append((cve_id, doc_id))

                if len(buffer) >= BATCH_SIZE:
                    await conn.copy_records_to_table(
                        "epss_lineage_stage",
                        records=buffer,
                        columns=["cve_id", "doc_id"],
                    )
                    buffer.clear()

            if buffer:
                await conn.copy_records_to_table(
                    "epss_lineage_stage",
                    records=buffer,
                    columns=["cve_id", "doc_id"],
                )

            staged = await conn.fetchval(
                "SELECT count(*) FROM epss_lineage_stage"
            )
            archive_records += staged

            eligible = await conn.fetchval("""
                SELECT count(*)
                FROM epss_lineage_stage s
                JOIN public.vulnerabilities v
                  ON v.cve_id = s.cve_id
                 AND s.doc_id = ANY(v.provenance)
                LEFT JOIN public.raw_documents rd
                  ON rd.doc_id = s.doc_id
                WHERE rd.doc_id IS NULL
            """)
            eligible_total += eligible

            inserted_this_snapshot = 0

            for start in range(1, staged + 1, BATCH_SIZE):
                end = min(start + BATCH_SIZE, staged + 1)

                async with conn.transaction():
                    status = await conn.execute("""
                        INSERT INTO public.raw_documents (
                            doc_id, source_id, url, content_sha256,
                            content_type, object_key, fetched_at
                        )
                        SELECT
                            s.doc_id, $3, $4, $5, $6, $7, $8
                        FROM epss_lineage_stage s
                        WHERE s.seq >= $1
                          AND s.seq < $2
                          AND EXISTS (
                              SELECT 1
                              FROM public.vulnerabilities v
                              WHERE v.cve_id = s.cve_id
                                AND s.doc_id = ANY(v.provenance)
                          )
                        ON CONFLICT (doc_id) DO NOTHING
                    """,
                    start, end,
                    meta["source_id"], meta["url"],
                    meta["content_sha256"], meta["content_type"],
                    meta["object_key"], meta["fetched_at"])

                inserted_this_snapshot += int(status.split()[-1])

            inserted_total += inserted_this_snapshot

            print({
                "snapshot": f"{number}/{len(snapshots)}",
                "fetched_at": str(meta["fetched_at"]),
                "staged_records": staged,
                "eligible_missing": eligible,
                "inserted": inserted_this_snapshot,
                "total_inserted": inserted_total,
            }, flush=True)

        # Verify all provenance references that were reconstructed from
        # these archives and still existed during insertion.
        remaining = await conn.fetchval("""
            WITH refs AS (
                SELECT DISTINCT v.cve_id, p.ref
                FROM public.vulnerabilities v
                CROSS JOIN LATERAL unnest(v.provenance) AS p(ref)
            )
            SELECT count(*)
            FROM refs r
            WHERE EXISTS (
                SELECT 1 FROM public.raw_documents rd
                WHERE rd.doc_id = r.ref
                  AND rd.source_id = 'epss'
            )
              AND NOT EXISTS (
                SELECT 1 FROM public.raw_documents rd
                WHERE rd.doc_id = r.ref
            )
        """)

        after_vulns = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerabilities"
        )
        after_history = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerability_versions"
        )
        total_docs = await conn.fetchval(
            "SELECT count(*) FROM public.raw_documents"
        )

        print("\n========== BACKFILL SUMMARY ==========")
        print("Snapshots processed:", len(snapshots))
        print("Distinct reconstructed records staged across snapshots:",
              archive_records)
        print("Missing candidates counted during processing:", eligible_total)
        print("New rows inserted:", inserted_total)
        print("Raw documents after:", total_docs)
        print("Unresolved references from restored EPSS rows:", remaining)
        print("Vulnerability rows before/after:",
              before_vulns, after_vulns)
        print("History rows before/after:",
              before_history, after_history)
        print("Elapsed seconds:", round(time.monotonic() - started, 2))

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import hashlib
import json
import os
import asyncpg

from raven_common import storage
from parsers import PARSERS

BATCH_SIZE = 2000
SOURCE_ID = "epss"


def doc_id_for(source_id: str, payload: dict) -> str:
    key = (
        f"{source_id}:{payload.get('cve_id', '')}:"
        f"{json.dumps(payload, sort_keys=True, default=str)}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:40]


async def main():
    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])

    try:
        meta = await conn.fetchrow("""
            SELECT rd.source_id, rd.url, rd.content_sha256,
                   rd.content_type, rd.object_key, rd.fetched_at,
                   s.parser
            FROM public.raw_documents rd
            JOIN public.sources s USING (source_id)
            WHERE rd.source_id = $1
              AND rd.object_key IS NOT NULL
            ORDER BY rd.fetched_at DESC
            LIMIT 1
        """, SOURCE_ID)

        if not meta:
            raise RuntimeError("No archived EPSS snapshot found")

        print("Reading archive:", meta["object_key"], flush=True)

        raw = await asyncio.to_thread(storage.get_raw, meta["object_key"])
        digest = hashlib.sha256(raw).hexdigest()

        if digest != meta["content_sha256"]:
            raise RuntimeError("Archive checksum mismatch; aborting")

        mode, parser = PARSERS[meta["parser"]]
        payload = json.loads(raw) if mode == "json" else raw
        records = parser(payload)

        # Reconstruct the original document IDs and deduplicate the stage.
        staged = {}
        for rec in records:
            if not rec.get("cve_id"):
                continue
            doc_id = doc_id_for(SOURCE_ID, rec)
            staged.setdefault(doc_id, (rec["cve_id"], doc_id))

        if not staged:
            raise RuntimeError("Snapshot produced no document records")

        print("Checksum verified: True", flush=True)
        print("Parsed records:", len(records), flush=True)
        print("Distinct reconstructed IDs:", len(staged), flush=True)

        # Preserve the current vulnerability and history counts for validation.
        before_vulns = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerabilities"
        )
        before_history = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerability_versions"
        )

        # Use a temporary staging table so COPY is efficient.
        await conn.execute("""
            CREATE TEMP TABLE epss_lineage_stage (
                seq bigint PRIMARY KEY,
                cve_id text NOT NULL,
                doc_id text NOT NULL UNIQUE,
                source_id text NOT NULL,
                url text NOT NULL,
                content_sha256 text NOT NULL,
                content_type text NOT NULL,
                object_key text NOT NULL,
                fetched_at timestamptz NOT NULL
            ) ON COMMIT PRESERVE ROWS
        """)

        stage_rows = [
            (
                seq,
                cve_id,
                doc_id,
                SOURCE_ID,
                meta["url"],
                meta["content_sha256"],
                meta["content_type"],
                meta["object_key"],
                meta["fetched_at"],
            )
            for seq, (cve_id, doc_id)
            in enumerate(staged.values(), start=1)
        ]

        await conn.copy_records_to_table(
            "epss_lineage_stage",
            records=stage_rows,
            columns=[
                "seq", "cve_id", "doc_id", "source_id",
                "url", "content_sha256", "content_type",
                "object_key", "fetched_at",
            ],
        )

        total = len(stage_rows)

        # Do not backfill IDs that are no longer in current vulnerability
        # provenance. Abort if the provenance reproduction is inconsistent.
        referenced = await conn.fetchval("""
            SELECT count(*)
            FROM epss_lineage_stage s
            WHERE EXISTS (
                SELECT 1
                FROM public.vulnerabilities v
                WHERE v.cve_id = s.cve_id
                  AND s.doc_id = ANY(v.provenance)
            )
        """)

        if referenced != total:
            raise RuntimeError(
                f"Only {referenced}/{total} reconstructed IDs are "
                "referenced by current vulnerabilities; refusing bulk write"
            )

        already_present = await conn.fetchval("""
            SELECT count(*)
            FROM epss_lineage_stage s
            JOIN public.raw_documents rd ON rd.doc_id = s.doc_id
        """)

        print("Referenced reconstructed IDs:", referenced, flush=True)
        print("Already registered:", already_present, flush=True)
        print("Batch size:", BATCH_SIZE, flush=True)
        print("Starting resumable backfill...", flush=True)

        inserted_total = 0
        batches = 0

        for start in range(1, total + 1, BATCH_SIZE):
            end = min(start + BATCH_SIZE, total + 1)

            # Each batch commits independently. If interrupted, rerunning
            # the script is safe because existing document IDs are skipped.
            async with conn.transaction():
                status = await conn.execute("""
                    INSERT INTO public.raw_documents (
                        doc_id, source_id, url, content_sha256,
                        content_type, object_key, fetched_at
                    )
                    SELECT
                        s.doc_id, s.source_id, s.url, s.content_sha256,
                        s.content_type, s.object_key, s.fetched_at
                    FROM epss_lineage_stage s
                    JOIN public.vulnerabilities v
                      ON v.cve_id = s.cve_id
                     AND s.doc_id = ANY(v.provenance)
                    WHERE s.seq >= $1
                      AND s.seq < $2
                    ON CONFLICT (doc_id) DO NOTHING
                """, start, end)

            inserted = int(status.split()[-1])
            inserted_total += inserted
            batches += 1

            if batches % 10 == 0 or end == total + 1:
                print(
                    f"Progress: {min(end - 1, total)}/{total}; "
                    f"new rows this run: {inserted_total}",
                    flush=True,
                )

        # Verify all reconstructed records from this snapshot now exist.
        remaining = await conn.fetchval("""
            SELECT count(*)
            FROM epss_lineage_stage s
            WHERE NOT EXISTS (
                SELECT 1
                FROM public.raw_documents rd
                WHERE rd.doc_id = s.doc_id
            )
        """)

        after_vulns = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerabilities"
        )
        after_history = await conn.fetchval(
            "SELECT count(*) FROM public.vulnerability_versions"
        )
        epss_rows = await conn.fetchval("""
            SELECT count(*)
            FROM public.raw_documents
            WHERE source_id = $1
        """, SOURCE_ID)
        total_docs = await conn.fetchval(
            "SELECT count(*) FROM public.raw_documents"
        )

        print("\n========== BACKFILL SUMMARY ==========")
        print("Snapshot records:", total)
        print("Already registered before run:", already_present)
        print("New rows inserted this run:", inserted_total)
        print("EPSS document rows after:", epss_rows)
        print("All raw document rows after:", total_docs)
        print("Snapshot IDs still missing:", remaining)
        print("Vulnerability rows before/after:",
              before_vulns, after_vulns)
        print("History rows before/after:",
              before_history, after_history)

        assert remaining == 0, "Some reconstructed IDs are still missing"
        assert before_vulns == after_vulns, "Vulnerability rows changed"
        assert before_history == after_history, "History rows changed"

        print("PASS: EPSS lineage backfill verified", flush=True)

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

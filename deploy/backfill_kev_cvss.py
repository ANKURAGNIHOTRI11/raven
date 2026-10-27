"""One-off backfill for the merge() bug fixed in services/normalizer/main.py.

See the module docstring history: this re-fetches NVD's own record for every
KEV-listed CVE still sitting at cvss_base=0 and corrects it directly.

Parallelized with a bounded worker pool plus a sliding-window rate limiter
tuned just under NVD's documented limits (50 req/30s with an API key,
5 req/30s without) - concurrency lets us actually saturate that rate instead
of being bottlenecked by each request's round-trip latency, which a purely
sequential loop with a flat per-request sleep cannot do.

Run via the crawler service so it inherits the right network, RAVEN_PG_DSN
and RAVEN_NVD_API_KEY without any extra setup:

    docker compose run --rm \
      -v "$(pwd)/deploy/backfill_kev_cvss.py:/app/backfill_kev_cvss.py:ro" \
      crawler python backfill_kev_cvss.py

Safe to re-run or interrupt - it only ever touches rows still at
cvss_base=0, so a partial run picks up where it left off.
"""
from __future__ import annotations

import asyncio
import collections
import os
import sys
import time

import asyncpg
import httpx

DSN = os.environ["RAVEN_PG_DSN"]
NVD_API_KEY = os.environ.get("RAVEN_NVD_API_KEY", "")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Stay a little under NVD's documented ceiling (50/30s with a key, 5/30s
# without) rather than riding the exact edge.
MAX_REQUESTS = 45 if NVD_API_KEY else 4
WINDOW_SECONDS = 30.0
CONCURRENCY = 5 if NVD_API_KEY else 2


class RateLimiter:
    """Sliding-window limiter: at most max_requests in any window_seconds."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self.times: collections.deque[float] = collections.deque()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                while self.times and now - self.times[0] > self.window:
                    self.times.popleft()
                if len(self.times) < self.max_requests:
                    self.times.append(now)
                    return
                sleep_for = self.window - (now - self.times[0]) + 0.05
            await asyncio.sleep(sleep_for)


def best_cvss(cve_obj: dict) -> tuple[float, str, str, str] | None:
    """Prefer v3.1 > v3.0 > v2, matching what the normalizer itself does."""
    metrics = cve_obj.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            severity = (data.get("baseSeverity") or "none").lower()
            return float(data["baseScore"]), data["vectorString"], version, severity
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0]["cvssData"]
        score = float(data["baseScore"])
        severity = "critical" if score >= 9 else "high" if score >= 7 else \
                   "medium" if score >= 4 else "low" if score > 0 else "none"
        return score, data["vectorString"], "2.0", severity
    return None


async def process_one(
    cve_id: str, i: int, total: int,
    client: httpx.AsyncClient, pool: asyncpg.Pool,
    limiter: RateLimiter, sem: asyncio.Semaphore, counts: dict,
) -> None:
    async with sem:
        await limiter.acquire()
        try:
            r = await client.get(NVD_URL, params={"cveId": cve_id})
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                counts["no_cvss_upstream"] += 1
                return
            cvss = best_cvss(vulns[0]["cve"])
            if cvss is None:
                counts["no_cvss_upstream"] += 1
                return
            base, vector, version, severity = cvss
            async with pool.acquire() as conn:
                tag = await conn.execute(
                    """UPDATE vulnerabilities
                       SET cvss_base=$1, cvss_vector=$2, cvss_version=$3,
                           severity=$4, source_trust=GREATEST(source_trust, 0.95),
                           normalized_at=now()
                       WHERE cve_id=$5 AND cvss_base=0""",
                    base, vector, version, severity, cve_id,
                )
            if tag.endswith(" 1"):
                counts["fixed"] += 1
                print(f"[{i}/{total}] fixed {cve_id}: cvss_base={base} severity={severity}", flush=True)
        except Exception as exc:
            counts["errors"] += 1
            print(f"[{i}/{total}] ERROR {cve_id}: {exc}", file=sys.stderr, flush=True)


async def main() -> None:
    pool = await asyncpg.create_pool(DSN, min_size=2, max_size=CONCURRENCY + 2)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT cve_id FROM vulnerabilities WHERE kev = true AND cvss_base = 0 ORDER BY cve_id"
        )
    cve_ids = [r["cve_id"] for r in rows]
    total = len(cve_ids)
    print(f"{total} corrupted KEV rows to backfill "
          f"(concurrency={CONCURRENCY}, rate<={MAX_REQUESTS}/{int(WINDOW_SECONDS)}s)", flush=True)
    if not NVD_API_KEY:
        print("WARNING: RAVEN_NVD_API_KEY not set - running at the slow "
              "unauthenticated rate limit, this will take a while", flush=True)

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    limiter = RateLimiter(MAX_REQUESTS, WINDOW_SECONDS)
    sem = asyncio.Semaphore(CONCURRENCY)
    counts = {"fixed": 0, "no_cvss_upstream": 0, "errors": 0}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        await asyncio.gather(*[
            process_one(cve_id, i, total, client, pool, limiter, sem, counts)
            for i, cve_id in enumerate(cve_ids, 1)
        ])

    await pool.close()
    print(f"\ndone: {counts['fixed']} fixed, "
          f"{counts['no_cvss_upstream']} had no CVSS at NVD either, {counts['errors']} errors")


if __name__ == "__main__":
    asyncio.run(main())

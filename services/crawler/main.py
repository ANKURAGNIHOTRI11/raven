"""Crawler engine.

Polls the source registry, fetches each enabled feed on its own cadence,
writes the untouched bytes to the WORM raw zone, and publishes one
RawDocument per extracted record onto the ingestion bus.

Resilience: per-source circuit breaker (opens after N consecutive failures,
half-opens on a timer), exponential backoff with jitter on transient errors,
and a dead-letter path - anything that fetches but will not parse is pushed to
the quarantine topic rather than dropped silently.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from raven_common import bus, db, storage, topics
from raven_common.models import QuarantineRecord, RawDocument, SourceClass
from raven_common.runtime import bootstrap, run
from raven_common.metrics import ERRORS, QUARANTINED, STAGE_LATENCY

from parsers import PARSERS
from scheduler import BoundedRunner, due_sources

SERVICE = "crawler"
FAILURE_THRESHOLD = 5
BREAKER_COOLDOWN = timedelta(minutes=15)
settings, log = bootstrap(SERVICE)


def doc_id_for(source_id: str, payload: dict) -> str:
    key = f"{source_id}:{payload.get('cve_id','')}:{json.dumps(payload, sort_keys=True, default=str)}"
    return hashlib.sha256(key.encode()).hexdigest()[:40]


async def load_sources() -> list[dict]:
    async with db.conn() as c:
        rows = await c.fetch(
            "SELECT * FROM sources WHERE enabled "
            "AND (circuit_open_until IS NULL OR circuit_open_until < now())"
        )
    return [dict(r) for r in rows]


async def mark_success(source_id: str, accepted: int) -> None:
    async with db.conn() as c:
        await c.execute(
            "UPDATE sources SET last_success=now(), consecutive_failures=0, "
            "circuit_open_until=NULL, last_error=NULL, "
            "accepted_records=accepted_records+$2 WHERE source_id=$1",
            source_id, accepted,
        )


async def mark_failure(source_id: str, error: str) -> None:
    async with db.conn() as c:
        row = await c.fetchrow(
            "UPDATE sources SET consecutive_failures=consecutive_failures+1, "
            "last_error=$2 WHERE source_id=$1 RETURNING consecutive_failures",
            source_id, error[:500],
        )
        if row and row["consecutive_failures"] >= FAILURE_THRESHOLD:
            until = datetime.now(timezone.utc) + BREAKER_COOLDOWN
            await c.execute(
                "UPDATE sources SET circuit_open_until=$2 WHERE source_id=$1", source_id, until
            )
            log.warning("circuit_open", source=source_id, until=until.isoformat())


def build_request(src: dict) -> tuple[str, dict, dict | None]:
    """Returns (url, params, headers)."""
    since = (datetime.now(timezone.utc) - timedelta(days=settings.feed_lookback_days))
    url, params, headers = src["url"], {}, {"User-Agent": "RAVEN/1.0 (+security-intel)"}
    if src["parser"] == "nvd":
        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 2000,
        }
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
    elif src["parser"] == "ghsa":
        params = {"per_page": 100, "published": f">{since.date().isoformat()}"}
        headers["Accept"] = "application/vnd.github+json"
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
    elif src["parser"] == "otx":
        params = {"limit": 50, "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S")}
        if settings.otx_api_key:
            headers["X-OTX-API-KEY"] = settings.otx_api_key
    elif src["parser"] == "redhat":
        params = {"after": since.date().isoformat(), "per_page": 500}
    return url, params, headers


PAGINATED_PARSERS = {"ghsa", "otx"}
MAX_PAGES = 5


async def fetch_paginated(client: httpx.AsyncClient, src: dict) -> list:
    """GitHub and OTX both spread results across pages rather than one
    response. Follow up to MAX_PAGES and return the combined item list - a
    poll cadence of 1-2 hours means a handful of pages covers the window."""
    url, params, headers = build_request(src)
    items: list = []
    next_url = url
    for _ in range(MAX_PAGES):
        r = await client.get(next_url, params=params if next_url == url else None,
                              headers=headers, timeout=90)
        r.raise_for_status()
        data = r.json()
        if src["parser"] == "ghsa":
            batch = data if isinstance(data, list) else data.get("advisories", [])
            items.extend(batch)
            m = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link", ""))
            if not m or not batch:
                break
            next_url = m.group(1)
        else:  # otx
            batch = data.get("results", [])
            items.extend(batch)
            next_url = data.get("next")
            if not next_url:
                break
    return items



OSV_PACKAGES = [
    ("PyPI", "torch"), ("PyPI", "transformers"), ("PyPI", "vllm"),
    ("PyPI", "fastapi"), ("PyPI", "uvicorn"), ("PyPI", "aiokafka"),
    ("PyPI", "httpx"), ("PyPI", "pydantic"), ("PyPI", "asyncpg"),
    ("Go", "github.com/docker/docker"),
]


async def fetch_osv(client: httpx.AsyncClient, src: dict) -> bytes:
    """OSV has no 'recent' feed: query by the packages we actually run, then
    hydrate each returned id. Returns {"vulns": [...]} for parse_osv."""
    base = "https://api.osv.dev/v1"
    headers = {"User-Agent": "RAVEN/1.0 (+security-intel)"}
    queries = [{"package": {"ecosystem": e, "name": n}} for e, n in OSV_PACKAGES]
    r = await client.post(f"{base}/querybatch", json={"queries": queries},
                          headers=headers, timeout=60)
    r.raise_for_status()
    ids: list[str] = []
    for res in r.json().get("results", []):
        for v in res.get("vulns", []):
            if v.get("id") and v["id"] not in ids:
                ids.append(v["id"])
    vulns = []
    for vid in ids[:200]:
        vr = await client.get(f"{base}/vulns/{vid}", headers=headers, timeout=30)
        if vr.status_code == 200:
            vulns.append(vr.json())
    return json.dumps({"vulns": vulns}).encode()

async def fetch_once(client: httpx.AsyncClient, src: dict) -> bytes:
    if src["parser"] == "osv":
        return await fetch_osv(client, src)
    url, params, headers = build_request(src)
    if url.startswith("file://"):
        return Path(url.replace("file://", "")).read_bytes()
    delay = 1.0
    last: Exception | None = None
    for attempt in range(4):
        try:
            r = await client.get(url, params=params or None, headers=headers, timeout=90)
            if r.status_code == 429 or 500 <= r.status_code < 600:
                raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
            r.raise_for_status()
            return r.content
        except Exception as exc:
            last = exc
            await asyncio.sleep(delay + random.uniform(0, 0.8))
            delay *= 2
    raise RuntimeError(f"fetch failed after retries: {last}")


async def harvest(client: httpx.AsyncClient, src: dict, producer: bus.Producer) -> int:
    mode, parser = PARSERS.get(src["parser"], ("json", lambda p: []))
    with STAGE_LATENCY.labels(SERVICE, "fetch").time():
        if src["parser"] in PAGINATED_PARSERS:
            items = await fetch_paginated(client, src)
            raw = json.dumps(items).encode()
        else:
            raw = await fetch_once(client, src)

    object_key, digest = await asyncio.to_thread(
        storage.put_raw, src["source_id"], raw,
        "application/json" if mode == "json" else "application/octet-stream",
    )

    try:
        records = parser(json.loads(raw) if mode == "json" else raw)
    except Exception as exc:
        QUARANTINED.labels(src["source_id"], "unparseable").inc()
        await producer.send(topics.QUARANTINE, QuarantineRecord(
            doc_id=digest[:40], source_id=src["source_id"], reason="unparseable",
            detail=str(exc)[:500], raw_excerpt=raw[:500].decode("utf-8", "replace"),
        ))
        raise

    sent = 0
    for rec in records:
        doc = RawDocument(
            doc_id=doc_id_for(src["source_id"], rec),
            source_id=src["source_id"],
            source_class=SourceClass(src["source_class"]),
            url=src["url"],
            content_sha256=digest,
            content_type="application/json",
            object_key=object_key,
            payload=rec,
            trust=float(src["trust"]),
        )
        async with db.conn() as c:
            await c.execute(
                "INSERT INTO raw_documents (doc_id, source_id, url, content_sha256, "
                "content_type, object_key) VALUES ($1,$2,$3,$4,$5,$6) "
                "ON CONFLICT DO NOTHING",
                doc.doc_id, doc.source_id, doc.url, doc.content_sha256,
                doc.content_type, doc.object_key,
            )
        await producer.send(topics.RAW_DOCUMENTS, doc, key=str(rec.get("cve_id", doc.doc_id)))
        sent += 1
    return sent


async def seed_assets(producer: bus.Producer) -> None:
    """Load the internal CMDB/SBOM inventory. Internal data bypasses the
    media-trust path but still goes through contract validation."""
    from raven_common.models import Asset

    path = Path(os.environ.get("RAVEN_CMDB_SEED_PATH", "/seed/assets.json"))
    if not path.exists():
        log.info("cmdb_seed_missing", path=str(path))
        return
    for item in json.loads(path.read_text()):
        asset = Asset.model_validate(item)
        async with db.conn() as c:
            await c.execute(
                """INSERT INTO assets (asset_id, hostname, kind, environment, criticality,
                   internet_exposed, owner, zone, cpe_uris, packages,
                   compensating_controls, connects_to, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
                   ON CONFLICT (asset_id) DO UPDATE SET
                     hostname=EXCLUDED.hostname, criticality=EXCLUDED.criticality,
                     internet_exposed=EXCLUDED.internet_exposed, packages=EXCLUDED.packages,
                     cpe_uris=EXCLUDED.cpe_uris, connects_to=EXCLUDED.connects_to,
                     compensating_controls=EXCLUDED.compensating_controls, updated_at=now()""",
                asset.asset_id, asset.hostname, asset.kind, asset.environment,
                asset.criticality, asset.internet_exposed, asset.owner, asset.zone,
                asset.cpe_uris, asset.packages, asset.compensating_controls,
                asset.connects_to,
            )
        await producer.send(topics.ASSET_EVENTS, asset, key=asset.asset_id)
    log.info("cmdb_seeded", path=str(path))


async def main() -> None:
    await bus.wait_for_bus()
    await bus.ensure_topics(topics.ALL_TOPICS)
    await asyncio.to_thread(storage.ensure_bucket)
    producer = await bus.Producer(SERVICE).start()
    await seed_assets(producer)

    next_run: dict[str, datetime] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        async def work(src: dict) -> int:
            return await harvest(client, src, producer)

        async def on_success(src: dict, count: int) -> None:
            await mark_success(src["source_id"], count)
            log.info("harvested", source=src["source_id"], records=count)

        async def on_failure(src: dict, exc: Exception) -> None:
            # str(TimeoutError()) is empty - fall back to the type name so the
            # registry's last_error is never blank for a real failure.
            reason = str(exc) or type(exc).__name__
            ERRORS.labels(SERVICE, "harvest").inc()
            await mark_failure(src["source_id"], reason)
            log.warning("harvest_failed", source=src["source_id"], error=reason[:300])

        # One task per source, so a slow or dead feed cannot hold up the rest.
        runner = BoundedRunner(
            work, on_success, on_failure,
            concurrency=int(os.environ.get("RAVEN_CRAWL_CONCURRENCY", "8")),
            timeout=float(os.environ.get("RAVEN_HARVEST_TIMEOUT", "300")),
        )
        while True:
            now = datetime.now(timezone.utc)
            for src in due_sources(await load_sources(), next_run, runner.in_flight(), now):
                next_run[src["source_id"]] = now + timedelta(seconds=int(src["poll_seconds"]))
                runner.dispatch(src)
            await asyncio.sleep(30)


if __name__ == "__main__":
    run(main, SERVICE)

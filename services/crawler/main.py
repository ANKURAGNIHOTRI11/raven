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


class IncompleteFetchError(RuntimeError):
    """A source response was truncated or could not be paged completely."""


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



async def mark_success(
    source_id: str,
    accepted: int,
    checkpoint_at: datetime | None = None,
) -> None:
    async with db.conn() as c:
        await c.execute(
            "UPDATE sources SET last_success=COALESCE($3, now()), "
            "consecutive_failures=0, circuit_open_until=NULL, last_error=NULL, "
            "accepted_records=accepted_records+$2 WHERE source_id=$1",
            source_id, accepted, checkpoint_at,
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
    """Build a source request using an incremental NVD modification window."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    since = now - timedelta(days=settings.feed_lookback_days)

    if src.get("parser") == "nvd":
        last_success = src.get("last_success")
        if isinstance(last_success, datetime):
            if last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=timezone.utc)
            else:
                last_success = last_success.astimezone(timezone.utc)
            since = min(last_success, now) - timedelta(minutes=5)

    since = since.replace(microsecond=0)
    url, params, headers = src["url"], {}, {
        "User-Agent": "RAVEN/1.0 (+security-intel)"
    }

    if src["parser"] == "nvd":
        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 2000,
        }
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

    elif src["parser"] == "ghsa":
        params = {
            "per_page": 100,
            "published": f">{since.date().isoformat()}",
        }
        headers["Accept"] = "application/vnd.github+json"
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

    elif src["parser"] == "otx":
        params = {
            "limit": 50,
            "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if settings.otx_api_key:
            headers["X-OTX-API-KEY"] = settings.otx_api_key

    elif src["parser"] == "redhat":
        params = {"after": since.date().isoformat(), "per_page": 500}

    return url, params, headers

PAGINATED_PARSERS = {"ghsa", "otx"}
MAX_PAGES = 30


async def fetch_paginated(client: httpx.AsyncClient, src: dict) -> list:
    """Fetch every page or fail; never report a truncated feed as successful."""
    url, params, headers = build_request(src)
    items: list = []
    next_url = url

    for page_no in range(MAX_PAGES):
        r = await client.get(
            next_url,
            params=params if next_url == url else None,
            headers=headers,
            timeout=90,
        )
        r.raise_for_status()
        data = r.json()

        if src["parser"] == "ghsa":
            if isinstance(data, list):
                batch = data
            elif isinstance(data, dict):
                if "advisories" not in data:
                    raise IncompleteFetchError(
                        "GHSA page is missing the advisories field"
                    )
                batch = data["advisories"]
            else:
                raise IncompleteFetchError("GHSA returned an invalid page shape")
            if not isinstance(batch, list):
                raise IncompleteFetchError("GHSA advisories field is not a list")

            items.extend(batch)
            match = re.search(
                r'<([^>]+)>;\s*rel="next"',
                r.headers.get("Link", ""),
            )
            if not match:
                break
            next_url = match.group(1)

        else:  # OTX
            if not isinstance(data, dict):
                raise IncompleteFetchError("OTX returned an invalid page shape")
            if "results" not in data:
                raise IncompleteFetchError(
                    "OTX page is missing the results field"
                )
            batch = data["results"]
            if not isinstance(batch, list):
                raise IncompleteFetchError("OTX results field is not a list")
            items.extend(batch)
            next_url = data.get("next")
            if not next_url:
                break

        if page_no == MAX_PAGES - 1:
            log.error(
                "paginated_cap_hit",
                source=src.get("source_id"),
                pages=MAX_PAGES,
                records=len(items),
            )
            raise IncompleteFetchError(
                f"{src.get('source_id')} exceeded MAX_PAGES={MAX_PAGES}"
            )

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

async def _get_with_retry(client: httpx.AsyncClient, url: str, params: dict | None,
                          headers: dict, delays: tuple[float, ...] = (1.0, 2.0, 4.0)) -> bytes:
    """GET with jittered backoff. Retries timeouts, connection errors, 429 and 5xx;
    other 4xx (bad key, bad request) fail immediately instead of burning retries."""
    last: Exception | None = None
    for attempt in range(len(delays) + 1):
        try:
            r = await client.get(url, params=params or None, headers=headers, timeout=90)
            if r.status_code == 429 or 500 <= r.status_code < 600:
                raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
            r.raise_for_status()
            return r.content
        except httpx.HTTPStatusError as exc:
            last = exc
            code = exc.response.status_code
            if code != 429 and code < 500:
                raise RuntimeError(f"fetch failed (HTTP {code}, not retryable): {exc}") from exc
        except Exception as exc:  # timeouts, resets, DNS
            last = exc
        if attempt < len(delays):
            await asyncio.sleep(delays[attempt] + random.uniform(0, 0.8))
    raise RuntimeError(f"fetch failed after retries: {type(last).__name__}: {last}")



NVD_MAX_PAGES = 50
NVD_DATE_WINDOW = timedelta(days=119)


async def fetch_nvd(client: httpx.AsyncClient, src: dict) -> bytes:
    """Fetch the complete NVD range or fail without advancing its checkpoint."""
    url, params, headers = build_request(src)
    date_format = "%Y-%m-%dT%H:%M:%S.000"

    overall_start = datetime.strptime(
        params["lastModStartDate"], date_format
    ).replace(tzinfo=timezone.utc)
    overall_end = datetime.strptime(
        params["lastModEndDate"], date_format
    ).replace(tzinfo=timezone.utc)

    if overall_start > overall_end:
        raise IncompleteFetchError("NVD date window ends before it starts")

    pause = 0.8 if "apiKey" in headers else 6.5
    merged_page = None
    all_vulnerabilities = []
    aggregate_total = 0
    window_start = overall_start

    while True:
        # A shared boundary is intentional: it prevents gaps in date coverage.
        # Any boundary duplicate is safe for RAVEN's idempotent record handling.
        window_end = min(window_start + NVD_DATE_WINDOW, overall_end)
        window_params = {
            **params,
            "lastModStartDate": window_start.strftime(date_format),
            "lastModEndDate": window_end.strftime(date_format),
        }

        start = 0
        window_total = None
        window_fetched = 0

        for page_no in range(NVD_MAX_PAGES):
            raw = await _get_with_retry(
                client,
                url,
                {**window_params, "startIndex": start},
                headers,
                delays=(5.0, 15.0, 45.0),
            )
            page = json.loads(raw)

            if not isinstance(page, dict):
                raise IncompleteFetchError("NVD returned a non-object page")

            vulnerabilities = page.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise IncompleteFetchError(
                    "NVD vulnerabilities field is not a list"
                )

            try:
                reported_start = int(page["startIndex"])
                got = int(page["resultsPerPage"])
                total = int(page["totalResults"])
            except (KeyError, TypeError, ValueError) as exc:
                raise IncompleteFetchError(
                    "NVD pagination metadata is missing or invalid"
                ) from exc

            if reported_start != start:
                raise IncompleteFetchError(
                    f"NVD offset mismatch: requested={start}, "
                    f"received={reported_start}"
                )
            if got < 0 or total < 0 or got != len(vulnerabilities):
                raise IncompleteFetchError(
                    "NVD pagination counts do not match returned records"
                )

            if window_total is None:
                window_total = total
                merged_page = dict(page) if merged_page is None else merged_page
            elif total != window_total:
                raise IncompleteFetchError(
                    "NVD totalResults changed during pagination"
                )

            if start + got > total:
                raise IncompleteFetchError(
                    "NVD page returned more records than totalResults"
                )

            all_vulnerabilities.extend(vulnerabilities)
            window_fetched += got

            if got == 0:
                if start < total:
                    raise IncompleteFetchError(
                        f"NVD made no pagination progress at offset {start} "
                        f"of {total}"
                    )
                break

            start += got
            if start >= total:
                break

            if page_no == NVD_MAX_PAGES - 1:
                log.error(
                    "nvd_page_cap_hit",
                    source=src.get("source_id"),
                    fetched=start,
                    total=total,
                )
                raise IncompleteFetchError(
                    f"NVD exceeded NVD_MAX_PAGES={NVD_MAX_PAGES}; "
                    f"fetched={start}, total={total}"
                )

            await asyncio.sleep(pause)

        if window_total is None or window_fetched != window_total:
            raise IncompleteFetchError(
                "NVD date window was not fetched completely"
            )

        aggregate_total += window_total
        if window_end >= overall_end:
            break
        window_start = window_end

    if merged_page is None:
        merged_page = {}

    merged_page["vulnerabilities"] = all_vulnerabilities
    merged_page["startIndex"] = 0
    merged_page["resultsPerPage"] = len(all_vulnerabilities)
    merged_page["totalResults"] = aggregate_total

    # on_success persists this only after parsing and publishing succeed.
    src["_nvd_checkpoint_at"] = overall_end
    return json.dumps(merged_page).encode()

async def fetch_once(client: httpx.AsyncClient, src: dict) -> bytes:
    if src["parser"] == "osv":
        return await fetch_osv(client, src)
    if src["parser"] == "nvd":
        return await fetch_nvd(client, src)
    url, params, headers = build_request(src)
    if url.startswith("file://"):
        return Path(url.replace("file://", "")).read_bytes()
    return await _get_with_retry(client, url, params, headers)


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
            await mark_success(
                src["source_id"],
                count,
                src.get("_nvd_checkpoint_at"),
            )
            log.info("harvested", source=src["source_id"], records=count)

        async def on_failure(src: dict, exc: Exception) -> None:
            # str(TimeoutError()) is empty - fall back to the type name so the
            # registry's last_error is never blank for a real failure.
            reason = str(exc) or type(exc).__name__
            ERRORS.labels(SERVICE, "harvest").inc()
            await mark_failure(src["source_id"], reason)
            log.warning("harvest_failed", source=src["source_id"], error=reason[:300])

        # One task per source, so a slow or dead feed cannot hold up the rest.

        def timeout_for_source(src: dict) -> float:
            if src.get("parser") != "nvd":
                return float(os.environ.get("RAVEN_HARVEST_TIMEOUT", "300"))

            per_window = float(
                os.environ.get("RAVEN_NVD_HARVEST_TIMEOUT", "900")
            )
            now = datetime.now(timezone.utc).replace(microsecond=0)
            last_success = src.get("last_success")

            if isinstance(last_success, datetime):
                if last_success.tzinfo is None:
                    last_success = last_success.replace(tzinfo=timezone.utc)
                else:
                    last_success = last_success.astimezone(timezone.utc)
                since = min(last_success, now) - timedelta(minutes=5)
            else:
                since = now - timedelta(days=settings.feed_lookback_days)

            span_seconds = max(0.0, (now - since).total_seconds())
            window_seconds = NVD_DATE_WINDOW.total_seconds()
            window_count = max(
                1,
                int((span_seconds + window_seconds - 1) // window_seconds),
            )
            return per_window * window_count

        runner = BoundedRunner(
            work, on_success, on_failure,
            concurrency=int(os.environ.get("RAVEN_CRAWL_CONCURRENCY", "8")),
            timeout=timeout_for_source,
        )
        while True:
            now = datetime.now(timezone.utc)
            for src in due_sources(await load_sources(), next_run, runner.in_flight(), now):
                next_run[src["source_id"]] = now + timedelta(seconds=int(src["poll_seconds"]))
                runner.dispatch(src)
            await asyncio.sleep(30)


if __name__ == "__main__":
    run(main, SERVICE)

"""Per-source scheduling for the crawler.

Kept free of import-time side effects (no settings, no metrics server, no
network) so it can be unit tested without the rest of the service.

Why this exists: the crawler used to poll every source in one serial loop, so
one slow or dead feed (4 attempts x 90 s timeout plus backoff, roughly 6
minutes) delayed every source queued behind it - and with a breaker threshold
of 5 failures, a single dead source could stall the others for ~30 minutes
before its breaker opened. Each source now runs as its own task, bounded by a
global concurrency cap and a hard per-harvest timeout, and a source whose
previous harvest is still running is never started a second time.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any, Awaitable, Callable

log = logging.getLogger("crawler.scheduler")

# Sources that are loaded or pushed some other way and must never be polled
# over HTTP by the generic loop.
SKIP_PARSERS = frozenset({"cmdb", "telegram"})


def initial_due_time(src: dict, now):
    """When a source this process has not scheduled yet should next run.

    The in-memory schedule is lost on every restart, which used to make every
    source immediately due - re-downloading the whole EPSS file and the NVD
    window each time the container was recreated. The registry already records
    last_success, so the schedule is rebuilt from it: poll_seconds after the
    last success. A source that has never succeeded is due immediately, and a
    last_success in the future (clock skew) is clamped so it cannot park a
    source for longer than one interval.
    """
    last = src.get("last_success")
    if last is None:
        return now
    interval = timedelta(seconds=int(src.get("poll_seconds") or 3600))
    return min(last + interval, now + interval)


def due_sources(sources: list[dict], next_run: dict, in_flight: set, now) -> list[dict]:
    """Sources that should start a harvest right now."""
    due = []
    for src in sources:
        sid = src["source_id"]
        if src["parser"] in SKIP_PARSERS:
            continue
        if sid in in_flight:
            continue
        due_at = next_run[sid] if sid in next_run else initial_due_time(src, now)
        if due_at > now:
            continue
        due.append(src)
    return due


class BoundedRunner:
    """Runs one harvest task per source, isolated from each other.

    work(src)            -> the harvest itself; raise on failure
    on_success(src, res) -> bookkeeping after a clean harvest
    on_failure(src, exc) -> bookkeeping after a failure *or a timeout*
    """

    def __init__(
        self,
        work: Callable[[dict], Awaitable[Any]],
        on_success: Callable[[dict, Any], Awaitable[None]],
        on_failure: Callable[[dict, Exception], Awaitable[None]],
        concurrency: int = 8,
        timeout: float = 300.0,
    ) -> None:
        self._work, self._ok, self._bad = work, on_success, on_failure
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._timeout = timeout
        self._tasks: dict[str, asyncio.Task] = {}

    def in_flight(self) -> set[str]:
        self._tasks = {sid: t for sid, t in self._tasks.items() if not t.done()}
        return set(self._tasks)

    def dispatch(self, src: dict) -> None:
        sid = src["source_id"]
        if sid in self.in_flight():
            return
        self._tasks[sid] = asyncio.create_task(self._guarded(src))

    async def _guarded(self, src: dict) -> None:
        # The timeout starts only once a concurrency slot is held, so time
        # spent queued behind other sources never counts against this one.
        async with self._sem:
            try:
                result = await asyncio.wait_for(self._work(src), self._timeout)
            except Exception as exc:  # includes TimeoutError
                await self._safe(self._bad, src, exc)
            else:
                await self._safe(self._ok, src, result)

    @staticmethod
    async def _safe(cb, *args) -> None:
        # A bookkeeping failure (e.g. the database blinking) must not kill the
        # task silently or take any other source down with it.
        try:
            await cb(*args)
        except Exception:
            log.exception("scheduler_callback_failed")

    async def drain(self) -> None:
        """Wait for everything in flight (used by tests and clean shutdown)."""
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

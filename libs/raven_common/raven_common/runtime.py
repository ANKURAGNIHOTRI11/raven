"""Boilerplate every long-running RAVEN worker shares."""
from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable, Callable

import structlog

from . import logging as rlog
from . import metrics
from .settings import Settings, get_settings


def bootstrap(service: str) -> tuple[Settings, structlog.BoundLogger]:
    s = get_settings()
    s.service_name = service
    log = rlog.configure(service, s.log_level)
    metrics.serve(s.metrics_port)
    log.info("service_starting", env=s.env, metrics_port=s.metrics_port)
    return s, log


def run(main: Callable[[], Awaitable[None]], service: str) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    task = loop.create_task(main())

    async def supervise() -> None:
        done, _ = await asyncio.wait(
            {task, loop.create_task(stop.wait())}, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done:
            task.result()
        else:
            task.cancel()

    try:
        loop.run_until_complete(supervise())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()

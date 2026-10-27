from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import asyncpg

from .settings import get_settings

_pool: asyncpg.Pool | None = None


async def pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        s = get_settings()
        last: Exception | None = None
        for _ in range(60):
            try:
                _pool = await asyncpg.create_pool(s.pg_dsn, min_size=1, max_size=8)
                return _pool
            except Exception as exc:  # database still booting
                last = exc
                await asyncio.sleep(2)
        raise RuntimeError(f"postgres unreachable: {last}")
    return _pool


@asynccontextmanager
async def conn():
    p = await pool()
    async with p.acquire() as c:
        yield c

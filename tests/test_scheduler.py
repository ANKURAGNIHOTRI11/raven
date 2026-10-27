import asyncio
import time
from datetime import datetime, timedelta, timezone

from scheduler import BoundedRunner, due_sources, initial_due_time

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


def src(sid, parser="rss"):
    return {"source_id": sid, "parser": parser}


def make_runner(work, concurrency=8, timeout=5.0):
    events = {"ok": [], "bad": []}

    async def ok(s, res):
        events["ok"].append((s["source_id"], res))

    async def bad(s, exc):
        events["bad"].append((s["source_id"], exc))

    return BoundedRunner(work, ok, bad, concurrency=concurrency, timeout=timeout), events


def test_slow_source_does_not_delay_fast_ones():
    """The acceptance criterion: one slow source must not hold up the others."""
    finished = []

    async def work(s):
        if s["source_id"] == "slow":
            await asyncio.sleep(0.4)
        finished.append(s["source_id"])
        return 1

    async def go():
        runner, _ = make_runner(work)
        t0 = time.monotonic()
        for sid in ("slow", "a", "b", "c"):
            runner.dispatch(src(sid))
        # wait only until the three fast ones are done
        while len([x for x in finished if x != "slow"]) < 3:
            await asyncio.sleep(0.01)
        fast_elapsed = time.monotonic() - t0
        await runner.drain()
        return fast_elapsed

    fast_elapsed = asyncio.run(go())
    assert finished[-1] == "slow"          # slow one finished last
    assert fast_elapsed < 0.3              # and never held the others back


def test_hanging_source_is_cut_off_and_recorded_as_failure():
    async def work(s):
        await asyncio.sleep(10)

    async def go():
        runner, events = make_runner(work, timeout=0.05)
        runner.dispatch(src("hung"))
        await runner.drain()
        return events

    events = asyncio.run(go())
    assert [sid for sid, _ in events["bad"]] == ["hung"]
    assert isinstance(events['bad'][0][1], asyncio.TimeoutError)
    assert events["ok"] == []


def test_one_failure_does_not_affect_other_sources():
    async def work(s):
        if s["source_id"] == "dead":
            raise RuntimeError("404")
        return 7

    async def go():
        runner, events = make_runner(work)
        for sid in ("dead", "alive1", "alive2"):
            runner.dispatch(src(sid))
        await runner.drain()
        return events

    events = asyncio.run(go())
    assert sorted(sid for sid, _ in events["ok"]) == ["alive1", "alive2"]
    assert [sid for sid, _ in events["bad"]] == ["dead"]


def test_concurrency_is_bounded():
    running = {"now": 0, "peak": 0}

    async def work(s):
        running["now"] += 1
        running["peak"] = max(running["peak"], running["now"])
        await asyncio.sleep(0.05)
        running["now"] -= 1

    async def go():
        runner, _ = make_runner(work, concurrency=2)
        for i in range(6):
            runner.dispatch(src(f"s{i}"))
        await runner.drain()

    asyncio.run(go())
    assert running["peak"] == 2


def test_time_spent_queued_does_not_count_against_timeout():
    async def work(s):
        await asyncio.sleep(0.08)

    async def go():
        # concurrency 1: the 3rd source queues ~0.16 s, longer than the 0.12 s
        # timeout, but must still succeed because its clock starts at its slot.
        runner, events = make_runner(work, concurrency=1, timeout=0.12)
        for sid in ("a", "b", "c"):
            runner.dispatch(src(sid))
        await runner.drain()
        return events

    events = asyncio.run(go())
    assert len(events["ok"]) == 3 and events["bad"] == []


def test_source_already_running_is_not_started_twice():
    calls = []

    async def work(s):
        calls.append(s["source_id"])
        await asyncio.sleep(0.1)

    async def go():
        runner, _ = make_runner(work)
        runner.dispatch(src("x"))
        await asyncio.sleep(0.01)
        runner.dispatch(src("x"))   # previous harvest still in flight
        await runner.drain()

    asyncio.run(go())
    assert calls == ["x"]


def test_bookkeeping_failure_does_not_kill_the_runner():
    async def work(s):
        return 1

    async def broken_ok(s, res):
        raise RuntimeError("database blinked")

    async def go():
        events = []

        async def bad(s, exc):
            events.append(s["source_id"])

        runner = BoundedRunner(work, broken_ok, bad, concurrency=4, timeout=1)
        runner.dispatch(src("a"))
        runner.dispatch(src("b"))
        await runner.drain()
        runner.dispatch(src("c"))        # still usable afterwards
        await runner.drain()
        return runner.in_flight()

    assert asyncio.run(go()) == set()


def test_due_sources_respects_schedule_skips_and_in_flight():
    sources = [src("due"), src("later"), src("busy"), src("cmdb", "cmdb"), src("tg", "telegram")]
    next_run = {"later": NOW + timedelta(seconds=60), "due": NOW - timedelta(seconds=1)}
    out = due_sources(sources, next_run, {"busy"}, NOW)
    assert [s["source_id"] for s in out] == ["due"]


def test_never_seen_source_is_due_immediately():
    assert [s["source_id"] for s in due_sources([src("new")], {}, set(), NOW)] == ["new"]


def with_history(sid, last_success, poll_seconds=3600):
    return {"source_id": sid, "parser": "rss", "last_success": last_success, "poll_seconds": poll_seconds}


def test_restart_does_not_repoll_a_source_that_succeeded_recently():
    """The restart thundering herd: a fresh process must honour last_success."""
    recent = with_history("nvd", NOW - timedelta(minutes=10), poll_seconds=3600)
    assert due_sources([recent], {}, set(), NOW) == []


def test_restart_polls_a_source_whose_interval_has_elapsed():
    stale = with_history("nvd", NOW - timedelta(minutes=90), poll_seconds=3600)
    assert [s["source_id"] for s in due_sources([stale], {}, set(), NOW)] == ["nvd"]


def test_each_source_uses_its_own_interval_after_restart():
    a_day = with_history("epss", NOW - timedelta(hours=5), poll_seconds=86400)    # not due
    two_h = with_history("ghsa", NOW - timedelta(hours=5), poll_seconds=7200)     # due
    out = due_sources([a_day, two_h], {}, set(), NOW)
    assert [s["source_id"] for s in out] == ["ghsa"]


def test_never_succeeded_source_is_due_even_with_a_poll_interval():
    s = with_history("talos", None, poll_seconds=14400)
    assert [x["source_id"] for x in due_sources([s], {}, set(), NOW)] == ["talos"]


def test_future_last_success_cannot_park_a_source_beyond_one_interval():
    skewed = with_history("x", NOW + timedelta(days=30), poll_seconds=3600)
    assert initial_due_time(skewed, NOW) == NOW + timedelta(seconds=3600)


def test_in_memory_schedule_still_wins_over_history():
    s = with_history("a", NOW - timedelta(hours=5), poll_seconds=3600)   # history says due
    assert due_sources([s], {"a": NOW + timedelta(seconds=60)}, set(), NOW) == []

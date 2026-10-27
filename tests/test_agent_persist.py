from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from raven_common.models import AgentAction, AgentDecision, RemediationPlan


ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "services" / "agents"

if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))


def load_agent_module():
    # Avoid starting the service's real metrics/bootstrap runtime in tests.
    import raven_common.runtime as runtime

    original_bootstrap = runtime.bootstrap
    runtime.bootstrap = lambda service: (
        None,
        logging.getLogger(f"test.{service}"),
    )

    name = "raven_agents_main_test"
    spec = importlib.util.spec_from_file_location(
        name, AGENT_DIR / "main.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load services/agents/main.py")

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module

    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    finally:
        runtime.bootstrap = original_bootstrap

    return module


agents_main = load_agent_module()


class FakeTransaction:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        self.connection.transactions_started += 1
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.connection.commits += 1
        else:
            self.connection.rollbacks += 1
        return False


class FakeConnection:
    def __init__(self, insert_results, fail_on_approval=False):
        self.insert_results = list(insert_results)
        self.fail_on_approval = fail_on_approval
        self.execute_calls = []
        self.transactions_started = 0
        self.commits = 0
        self.rollbacks = 0

    def transaction(self):
        return FakeTransaction(self)

    async def fetchval(self, query, *args):
        if not self.insert_results:
            raise AssertionError("Unexpected additional decision insert")
        return self.insert_results.pop(0)

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))

        if (
            self.fail_on_approval
            and "INSERT INTO approvals" in query
        ):
            raise RuntimeError("simulated approval insert failure")

        return "INSERT 0 1"


def install_fake_connection(monkeypatch, connection):
    @asynccontextmanager
    async def fake_conn():
        yield connection

    monkeypatch.setattr(agents_main.db, "conn", fake_conn)


def make_decision(action=AgentAction.ACT):
    plan = RemediationPlan(
        plan_id="plan-test-1",
        cve_id="CVE-2026-12345",
        asset_id="asset-test-1",
        summary="Test remediation plan",
        patch_commands=["package-manager update example-package"],
        validation=["verify installed version"],
        rollback=["restore previous package version"],
    )

    return AgentDecision(
        decision_id="decision-test-1",
        assessment_id="assessment-test-1",
        cve_id="CVE-2026-12345",
        asset_id="asset-test-1",
        action=action,
        confidence=0.8,
        plan=plan,
    )


def count_sql(connection, fragment):
    return sum(
        fragment.lower() in query.lower()
        for query, _ in connection.execute_calls
    )


def test_first_decision_creates_one_approval_and_audit(monkeypatch):
    connection = FakeConnection(["decision-test-1"])
    install_fake_connection(monkeypatch, connection)

    asyncio.run(agents_main.persist(make_decision()))

    assert count_sql(connection, "INSERT INTO approvals") == 1
    assert count_sql(connection, "INSERT INTO audit_log") == 1
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_repeated_decision_does_not_create_duplicate_rows(monkeypatch):
    # First INSERT wins; second is ON CONFLICT DO NOTHING RETURNING no row.
    connection = FakeConnection(["decision-test-1", None])
    install_fake_connection(monkeypatch, connection)

    decision = make_decision()
    asyncio.run(agents_main.persist(decision))
    asyncio.run(agents_main.persist(decision))

    assert count_sql(connection, "INSERT INTO approvals") == 1
    assert count_sql(connection, "INSERT INTO audit_log") == 1
    assert connection.transactions_started == 2
    assert connection.commits == 2
    assert connection.rollbacks == 0


def test_abstention_with_plan_remains_in_human_review_queue(monkeypatch):
    connection = FakeConnection(["decision-test-1"])
    install_fake_connection(monkeypatch, connection)

    asyncio.run(agents_main.persist(make_decision(AgentAction.ABSTAIN)))

    approval_calls = [
        args
        for query, args in connection.execute_calls
        if "INSERT INTO approvals" in query
    ]

    assert len(approval_calls) == 1
    assert approval_calls[0][1] == "pending"


def test_approval_failure_rolls_back_transaction(monkeypatch):
    connection = FakeConnection(
        ["decision-test-1"],
        fail_on_approval=True,
    )
    install_fake_connection(monkeypatch, connection)

    with pytest.raises(RuntimeError, match="simulated approval insert failure"):
        asyncio.run(agents_main.persist(make_decision()))

    assert connection.rollbacks == 1
    assert connection.commits == 0
    assert count_sql(connection, "INSERT INTO audit_log") == 0

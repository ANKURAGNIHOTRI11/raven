import orjson
import pytest

from raven_common.approval_policy import has_actionable_plan


VALID_PLAN = {
    "plan_id": "plan-1",
    "cve_id": "CVE-2026-12345",
    "asset_id": "asset-1",
    "summary": "Test remediation",
    "rollback": ["restore the previous version"],
}


@pytest.mark.parametrize(
    "value",
    [
        VALID_PLAN,
        orjson.dumps(VALID_PLAN),
        orjson.dumps(VALID_PLAN).decode(),
    ],
)
def test_valid_plan_is_actionable(value):
    assert has_actionable_plan(value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "null",
        b"null",
        {},
        "{}",
        "not-json",
        [],
        {**VALID_PLAN, "rollback": []},
        {**VALID_PLAN, "plan_id": ""},
    ],
)
def test_missing_or_invalid_plan_is_not_actionable(value):
    assert not has_actionable_plan(value)

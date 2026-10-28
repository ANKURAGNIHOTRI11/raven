from __future__ import annotations

from typing import Any

import orjson


def has_actionable_plan(value: Any) -> bool:
    """Return True only for a structurally usable remediation plan."""
    if isinstance(value, (str, bytes, bytearray)):
        try:
            value = orjson.loads(value)
        except orjson.JSONDecodeError:
            return False

    if not isinstance(value, dict):
        return False

    required_text = ("plan_id", "cve_id", "asset_id", "summary")
    if any(
        not isinstance(value.get(key), str) or not value[key].strip()
        for key in required_text
    ):
        return False

    rollback = value.get("rollback")
    return isinstance(rollback, list) and bool(rollback)

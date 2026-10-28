"""Strict gate for LLM verifier results."""
from __future__ import annotations

from typing import Any


def verification_passed(verdict: Any) -> bool:
    """Only a clean, structurally valid pass may be treated as verified."""
    if not isinstance(verdict, dict):
        return False
    return (
        str(verdict.get("verdict", "")).strip().lower() == "pass"
        and bool(verdict.get("grounded"))
        and not verdict.get("hallucinations")
        and not verdict.get("unsafe_steps")
        and not bool(verdict.get("missing_rollback"))
    )

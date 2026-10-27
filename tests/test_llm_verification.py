from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "llm_gateway"))
from verification_policy import verification_passed


def valid_verdict(**updates):
    result = {
        "verdict": "pass", "grounded": True, "notes": "supported",
        "adjusted_confidence": 0.9, "hallucinations": [],
        "unsafe_steps": [], "missing_rollback": False,
    }
    result.update(updates)
    return result


def test_clean_verifier_pass_is_accepted():
    assert verification_passed(valid_verdict())


def test_unchecked_verifier_is_not_accepted():
    assert not verification_passed(valid_verdict(verdict="unchecked"))


def test_verifier_failure_is_not_accepted():
    assert not verification_passed(valid_verdict(verdict="fail"))


def test_reported_unsafe_steps_or_hallucinations_override_pass():
    assert not verification_passed(valid_verdict(unsafe_steps=["destructive command"]))
    assert not verification_passed(valid_verdict(hallucinations=["unsupported claim"]))


def test_missing_rollback_or_non_object_is_not_accepted():
    assert not verification_passed(valid_verdict(missing_rollback=True))
    assert not verification_passed(None)

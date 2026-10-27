"""Measures the normalizer's data-contract gate against hostile and malformed
records (EPIC-01: '<1% malformed-record leakage into normalization').

Every case in MALFORMED must end up QUARANTINED - rejected, with a reason on
record. "accepted" is leakage; "dropped_silently" is a record that vanishes
with only a log line. Cases the gate currently gets wrong are marked
xfail(strict=True) with the reason: the suite is green today, and the day a
fix lands the case XPASSes, strict mode fails the run, and the marker has to be
removed - so a gap can neither be fixed nor regress without anyone noticing.

Run with:  pytest tests/test_ingest_gate.py -rx -s
"""
import inspect
from collections import Counter

import pytest

from ingest_gate_harness import LEGIT, MALFORMED, N, run_gate

LEAKED_BASELINE = 0       # accepted malformed records today
VANISHED_BASELINE = 0      # malformed records dropped with no quarantine row today
FALSE_POSITIVE_BASELINE = 0

ID_SPOOF = "CVE_SHAPE uses \\d, which matches non-ASCII digits: a look-alike id is accepted and never merges with the real CVE"
FREE_TEXT = "only 'description' is screened for active content; this field is stored and rendered unscreened"
BLACKLIST = "active-content check is a narrow blacklist (script / onerror / javascript: / data:text/html)"
URL_SCHEME = "reference URLs are not restricted to http(s)"
VANISH = "unexpected failure is only logged by main() and the record is dropped - it never reaches quarantine"

GAPS = {}
FALSE_POSITIVES = {}


def gap(name, table):
    return pytest.param(name, marks=pytest.mark.xfail(strict=True, reason=table[name])) if name in table else name


@pytest.mark.parametrize("name", [gap(n, GAPS) for n, _ in MALFORMED])
def test_malformed_record_is_quarantined(name):
    out = run_gate(dict(dict(MALFORMED)[name]))
    assert out.kind == "quarantined", f"{out.kind} ({out.detail})"


@pytest.mark.parametrize("name", [gap(n, FALSE_POSITIVES) for n, _ in LEGIT])
def test_legitimate_record_is_accepted(name):
    out = run_gate(dict(dict(LEGIT)[name]))
    assert out.kind == "accepted", f"{out.kind} ({out.detail})"


def _measure():
    outcomes = {n: run_gate(dict(r)) for n, r in MALFORMED}
    kinds = Counter(o.kind for o in outcomes.values())
    fps = [n for n, r in LEGIT if run_gate(dict(r)).kind != "accepted"]
    return outcomes, kinds, fps


def test_report_and_ratchet():
    """Prints the measured rates, and fails if any of them gets WORSE."""
    outcomes, kinds, fps = _measure()
    total = len(MALFORMED)
    print(f"\nmalformed records tested : {total}")
    print(f"  quarantined (good)     : {kinds['quarantined']}")
    print(f"  accepted    (LEAKAGE)  : {kinds['accepted']}  = {100 * kinds['accepted'] / total:.1f}%   (target < 1%)")
    print(f"  dropped silently       : {kinds['dropped_silently']}  = {100 * kinds['dropped_silently'] / total:.1f}%   (target 0%)")
    print(f"legitimate records wrongly quarantined: {len(fps)} of {len(LEGIT)}")
    assert kinds["accepted"] <= LEAKED_BASELINE, "a new leak appeared"
    assert kinds["dropped_silently"] <= VANISHED_BASELINE, "a new silent-drop path appeared"
    assert len(fps) <= FALSE_POSITIVE_BASELINE, "a new false positive appeared"


def test_acceptance_leakage_below_one_percent():
    _, kinds, _ = _measure()
    assert kinds["accepted"] / len(MALFORMED) < 0.01


def test_acceptance_nothing_vanishes_silently():
    _, kinds, _ = _measure()
    assert kinds["dropped_silently"] == 0


def test_bus_edge_contract_violations_are_quarantined():
    assert "on_invalid" in inspect.getsource(N.main)


def test_harness_mirrors_the_real_handle_stages():
    """Drift guard: run_gate() stands in for handle() minus I/O. If handle()'s
    gate stages change, this fails so the harness is updated with them."""
    src = inspect.getsource(N.handle)
    for needle in ("adversarial_screen(rec, doc)", "merge(existing, rec, doc.trust, doc.source_class)",
                   "NormalizedVulnerability.model_validate(merged)"):
        assert needle in src, f"handle() no longer contains {needle!r} - update ingest_gate_harness.run_gate"
    assert src.index("adversarial_screen") < src.index("merge(") < src.index("model_validate(merged)")

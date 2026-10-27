"""Autonomy policy.

The decision engine is allowed to be wrong; it is not allowed to be wrong
silently or expensively. Every gate below has to pass before an action can
reach production without a human, and any single failure demotes the decision
rather than blocking the pipeline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from raven_common.models import AgentAction, RemediationPlan, RiskAssessment

DESTRUCTIVE = re.compile(
    r"(rm\s+-rf\s+/(?!tmp|var/tmp)|mkfs\.|dd\s+if=.*of=/dev/(sd|nvme)|"
    r"DROP\s+DATABASE|TRUNCATE\s+TABLE|shutdown\s+-h|init\s+0|"
    r"iptables\s+-F|setenforce\s+0|systemctl\s+stop\s+(auditd|rsyslog|firewalld)|"
    r"chmod\s+-R\s+777\s+/|userdel|:\s*\(\)\s*\{.*\};:)", re.I,
)
SCOPE_ESCAPE = re.compile(r"(ansible\s+all|--limit\s+all|kubectl\s+.*--all-namespaces|"
                          r"for\s+host\s+in\s+\$\(cat|pssh|clush\s+-a)", re.I)


@dataclass
class Gate:
    name: str
    passed: bool
    detail: str = ""


def evaluate(
    assessment: RiskAssessment,
    plan: RemediationPlan | None,
    confidence: float,
    grounded: bool,
    verifier_verdict: str,
    guard_events: list[str],
    adversarial_flag: bool,
    conf_threshold: float,
    max_blast: int,
    abstain_floor: float,
) -> tuple[AgentAction, list[Gate], bool]:
    """Returns (action, gates, auto_approvable)."""
    blast = assessment.graph_signal.blast_radius if assessment.graph_signal else 0
    commands = "\n".join((plan.patch_commands if plan else []) + (plan.steps if plan else []))

    gates = [
        Gate("confidence", confidence >= conf_threshold, f"{confidence:.2f} vs {conf_threshold}"),
        Gate("grounded", grounded, "every claim carries a citation" if grounded else "ungrounded claims"),
        Gate("verifier", verifier_verdict == "pass", verifier_verdict),
        Gate("plan_present", plan is not None, ""),
        Gate("rollback_present", bool(plan and plan.rollback), ""),
        Gate("validation_present", bool(plan and plan.validation), ""),
        Gate("blast_radius", blast <= max_blast, f"{blast} assets vs limit {max_blast}"),
        Gate("non_destructive", not DESTRUCTIVE.search(commands), ""),
        Gate("scoped", not SCOPE_ESCAPE.search(commands), ""),
        Gate("no_injection", not guard_events, ",".join(guard_events[:3])),
        Gate("graph_trustworthy", not adversarial_flag, "robustness monitor flag"),
        Gate("non_prod_or_low_risk", True, ""),  # environment check filled by caller
    ]

    if confidence < abstain_floor or not grounded:
        return AgentAction.ABSTAIN, gates, False
    if all(g.passed for g in gates):
        return AgentAction.ACT, gates, True
    if confidence >= abstain_floor:
        return AgentAction.ANALYZE, gates, False
    return AgentAction.ABSTAIN, gates, False


def failed(gates: list[Gate]) -> list[str]:
    return [f"{g.name}({g.detail})" if g.detail else g.name for g in gates if not g.passed]

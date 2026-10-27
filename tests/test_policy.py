from raven_common.models import AgentAction, GraphSignal, RemediationPlan, RiskAssessment
from policy import evaluate

GOOD_PLAN = RemediationPlan(
    plan_id="p1", cve_id="CVE-2024-0001", asset_id="a1", summary="upgrade libfoo",
    steps=["apt-get update", "apt-get install -y libfoo=2.1.3"],
    patch_commands=["apt-get install -y libfoo=2.1.3"],
    validation=["dpkg -l libfoo | grep 2.1.3"],
    rollback=["apt-get install -y --allow-downgrades libfoo=2.1.2"],
)


def assessment(blast=1):
    return RiskAssessment(
        assessment_id="x", cve_id="CVE-2024-0001", asset_id="a1", fused_score=80,
        band="high", confidence=0.9,
        graph_signal=GraphSignal(cve_id="CVE-2024-0001", asset_id="a1", blast_radius=blast),
    )


def base(**kw):
    args = dict(assessment=assessment(), plan=GOOD_PLAN, confidence=0.92, grounded=True,
                verifier_verdict="pass", guard_events=[], adversarial_flag=False,
                conf_threshold=0.85, max_blast=3, abstain_floor=0.55)
    args.update(kw)
    return evaluate(**args)


def test_clean_case_can_act():
    action, _, auto = base()
    assert action is AgentAction.ACT and auto


def test_missing_rollback_blocks_action():
    plan = GOOD_PLAN.model_copy(update={"rollback": []})
    action, _, auto = base(plan=plan)
    assert action is not AgentAction.ACT and not auto


def test_destructive_command_blocks_action():
    plan = GOOD_PLAN.model_copy(update={"patch_commands": ["rm -rf /var/lib/important"]})
    action, _, _ = base(plan=plan)
    assert action is AgentAction.ANALYZE


def test_unscoped_change_blocks_action():
    plan = GOOD_PLAN.model_copy(update={"patch_commands": ["ansible all -m shell -a 'reboot'"]})
    action, _, _ = base(plan=plan)
    assert action is AgentAction.ANALYZE


def test_ungrounded_output_abstains():
    action, _, _ = base(grounded=False)
    assert action is AgentAction.ABSTAIN


def test_large_blast_radius_blocks_action():
    action, _, _ = base(assessment=assessment(blast=40))
    assert action is AgentAction.ANALYZE


def test_injection_event_blocks_action():
    action, _, _ = base(guard_events=["advisory:instruction_overridex1"])
    assert action is AgentAction.ANALYZE


def test_flagged_graph_signal_blocks_action():
    action, _, _ = base(adversarial_flag=True)
    assert action is AgentAction.ANALYZE

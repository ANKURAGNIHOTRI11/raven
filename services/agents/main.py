"""Multi-agent decision engine - novel layer 4.

Three outcomes, and the boring one is the default:

  ABSTAIN  low confidence or ungrounded -> straight to the human queue with a
           note about what evidence would settle it.
  ANALYZE  plausible but unproven -> the sandbox validates the *patch*, not the
           exploit: package resolution, config lint, service dependency check.
           Result goes to the human queue enriched.
  ACT      only when every gate in policy.py passes. Even then the action is a
           proposal attached to a mandatory rollback plan, and it only
           auto-approves inside a pre-scoped, non-production, low-blast-radius
           envelope. Production always waits for a person.

Nothing in this service executes anything on a managed host. It writes
approvals; the remediation worker applies them after a human decides.
"""
from __future__ import annotations

import hashlib
import uuid

import httpx
import orjson

from raven_common import bus, db, topics
from raven_common.metrics import DECISIONS, ERRORS, STAGE_LATENCY
from raven_common.models import (
    AgentAction, AgentDecision, RemediationPlan, RiskAssessment,
)
from raven_common.runtime import bootstrap, run

from policy import evaluate, failed

SERVICE = "agents"
settings, log = bootstrap(SERVICE)
GATEWAY = "http://llm-gateway:8000"
SANDBOX = "http://sandbox:8090"


async def load_context(a: RiskAssessment) -> tuple[dict, dict] | tuple[None, None]:
    async with db.conn() as c:
        v = await c.fetchrow("SELECT * FROM vulnerabilities WHERE cve_id=$1", a.cve_id)
        s = await c.fetchrow("SELECT * FROM assets WHERE asset_id=$1", a.asset_id)
    if not v or not s:
        return None, None
    vd, sd = dict(v), dict(s)
    vd["references_json"] = None
    for d in (vd, sd):
        for k, val in list(d.items()):
            if hasattr(val, "isoformat"):
                d[k] = val.isoformat()
    return vd, sd


async def sandbox_check(plan: RemediationPlan, asset: dict, client: httpx.AsyncClient) -> dict:
    """Patch validation in a disposable container. No exploit code is run -
    the sandbox proves the fix resolves and reverts, not that the bug fires."""
    try:
        r = await client.post(
            f"{SANDBOX}/validate",
            json={
                "asset_id": asset.get("asset_id"),
                "platform": asset.get("kind"),
                "packages": asset.get("packages", [])[:200],
                "patch_commands": plan.patch_commands,
                "validation": plan.validation,
                "rollback": plan.rollback,
            },
            timeout=240,
        )
        return r.json()
    except Exception as exc:
        return {"status": "unavailable", "detail": str(exc)[:200]}


async def persist(decision: AgentDecision) -> None:
    async with db.conn() as c:
        async with c.transaction():
            inserted_id = await c.fetchval(
                """INSERT INTO agent_decisions
                   (decision_id,assessment_id,cve_id,asset_id,action,
                    confidence,rationale,verifier_verdict,verifier_notes,
                    grounded,citations,plan,blast_radius,auto_approved,
                    guard_events,model_versions,decided_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                           $12::jsonb,$13,$14,$15,$16::jsonb,now())
                   ON CONFLICT (decision_id) DO NOTHING
                   RETURNING decision_id""",
                decision.decision_id, decision.assessment_id,
                decision.cve_id, decision.asset_id,
                decision.action.value, decision.confidence,
                decision.rationale, decision.verifier_verdict,
                decision.verifier_notes, decision.grounded,
                decision.citations,
                orjson.dumps(
                    decision.plan.model_dump() if decision.plan else None
                ).decode(),
                decision.blast_radius, decision.auto_approved,
                decision.guard_events,
                orjson.dumps(decision.model_versions).decode(),
            )

            # A repeated decision must not create another approval
            # or duplicate audit event.
            if inserted_id is None:
                return

            # Abstentions must never enter the remediation approval queue.
            if decision.plan:
                await c.execute(
                    """INSERT INTO approvals
                       (decision_id, state, rollback_plan)
                       VALUES ($1,$2,$3::jsonb)""",
                    decision.decision_id,
                    "approved" if decision.auto_approved else "pending",
                    orjson.dumps(
                        {"steps": decision.plan.rollback}
                    ).decode(),
                )

            await c.execute(
                """INSERT INTO audit_log
                   (actor, action, subject, detail)
                   VALUES ($1,$2,$3,$4::jsonb)""",
                "decision-engine",
                decision.action.value,
                f"{decision.cve_id}@{decision.asset_id}",
                orjson.dumps({
                    "confidence": decision.confidence,
                    "auto_approved": decision.auto_approved,
                }).decode(),
            )


async def handle(a: RiskAssessment, producer: bus.Producer, client: httpx.AsyncClient) -> None:
    vuln, asset = await load_context(a)
    if not vuln:
        return

    try:
        resp = await client.post(
            f"{GATEWAY}/v1/analyze",
            json={
                "vulnerability": vuln, "asset": asset,
                "assessment": a.model_dump(mode="json"), "want_remediation": True,
            },
            timeout=300,
        )
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        ERRORS.labels(SERVICE, "gateway").inc()
        log.warning("gateway_failed", cve=a.cve_id, error=str(exc)[:300])
        result = {"analysis": {}, "remediation": None, "verification": {"verdict": "unchecked"},
                  "confidence": 0.0, "grounded": False, "citations": [], "guard_events": [],
                  "model_versions": {}}

    analysis = result.get("analysis") or {}
    rem = result.get("remediation")
    plan = None
    if rem:
        plan = RemediationPlan(
            plan_id=str(uuid.uuid4())[:18],
            cve_id=a.cve_id, asset_id=a.asset_id,
            summary=str(rem.get("summary", ""))[:1000],
            steps=[str(x)[:600] for x in rem.get("steps", [])][:25],
            patch_commands=[str(x)[:600] for x in rem.get("patch_commands", [])][:25],
            iac_patch=str(rem.get("iac_patch", ""))[:8000],
            validation=[str(x)[:600] for x in rem.get("validation", [])][:15],
            rollback=[str(x)[:600] for x in rem.get("rollback", [])][:15],
            estimated_downtime_minutes=int(rem.get("estimated_downtime_minutes") or 0),
            requires_reboot=bool(rem.get("requires_reboot")),
            citations=[str(c) for c in rem.get("citations", [])][:20],
        )

    verification = result.get("verification") or {}
    confidence = float(result.get("confidence", 0.0))
    sig = a.graph_signal

    action, gates, auto_ok = evaluate(
        assessment=a, plan=plan, confidence=confidence,
        grounded=bool(result.get("grounded")),
        verifier_verdict=str(verification.get("verdict", "unchecked")),
        guard_events=list(result.get("guard_events", [])),
        adversarial_flag=bool(sig.adversarial_flag) if sig else False,
        conf_threshold=settings.autonomy_confidence_threshold,
        max_blast=settings.autonomy_max_blast_radius,
        abstain_floor=settings.abstain_confidence_floor,
    )

    # Production never auto-applies, whatever the gates say.
    auto_approved = bool(
        auto_ok and action is AgentAction.ACT and asset.get("environment") != "prod"
    )

    sandbox_result = {}
    if action is AgentAction.ANALYZE and plan:
        sandbox_result = await sandbox_check(plan, asset, client)
        if sandbox_result.get("status") == "patch_verified":
            confidence = min(0.98, confidence + 0.08)

    rationale_parts = [str(analysis.get("reasoning", ""))[:1500]]
    if analysis.get("attack_narrative"):
        rationale_parts.append("Attack narrative: " + str(analysis["attack_narrative"])[:1200])
    if failed(gates):
        rationale_parts.append("Gates not met: " + ", ".join(failed(gates)))
    if sandbox_result:
        rationale_parts.append(f"Sandbox: {sandbox_result.get('status')} "
                               f"{sandbox_result.get('detail','')}"[:400])

    decision = AgentDecision(
        decision_id=hashlib.sha1(f"{a.assessment_id}:{confidence}".encode()).hexdigest()[:32],
        assessment_id=a.assessment_id, cve_id=a.cve_id, asset_id=a.asset_id,
        action=action, confidence=round(confidence, 3),
        rationale="\n".join(p for p in rationale_parts if p),
        verifier_verdict=str(verification.get("verdict", "unchecked")),
        verifier_notes=str(verification.get("notes", ""))[:1500],
        grounded=bool(result.get("grounded")),
        citations=[str(c) for c in result.get("citations", [])][:25],
        plan=plan, blast_radius=sig.blast_radius if sig else 0,
        auto_approved=auto_approved,
        guard_events=[str(g) for g in result.get("guard_events", [])][:20],
        model_versions=result.get("model_versions", {}),
    )

    await persist(decision)
    DECISIONS.labels(action.value).inc()
    await producer.send(topics.AGENT_DECISIONS, decision, key=decision.decision_id)
    if action is AgentAction.ACT and plan:
        await producer.send(topics.REMEDIATIONS, decision, key=decision.decision_id)
    if not auto_approved:
        await producer.send(topics.HUMAN_QUEUE, decision, key=decision.decision_id)

    log.info("decided", cve=a.cve_id, asset=a.asset_id, action=action.value,
             confidence=decision.confidence, auto_approved=auto_approved,
             gates_failed=failed(gates))


async def main() -> None:
    await bus.wait_for_bus()
    producer = await bus.Producer(SERVICE).start()
    async with httpx.AsyncClient() as client:
        async for assessment in bus.consume(
            [topics.AGENT_TASKS], "agents", RiskAssessment, SERVICE
        ):
            with STAGE_LATENCY.labels(SERVICE, "decide").time():
                try:
                    await handle(assessment, producer, client)
                except Exception as exc:
                    ERRORS.labels(SERVICE, "decide").inc()
                    log.warning("decide_failed", cve=assessment.cve_id, error=str(exc)[:300])


if __name__ == "__main__":
    run(main, SERVICE)

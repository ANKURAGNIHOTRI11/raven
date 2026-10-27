"""Remediation agent.

Turns an approved decision into reviewable change artefacts: an Ansible
playbook with the forward steps, a matching revert playbook, and a validation
play. It writes them to the artefact volume and records the paths against the
approval.

It deliberately stops short of pushing changes to hosts. RAVEN's job is to get
a correct, reversible change into your existing change pipeline - the pipeline
you already trust with credentials - not to become a second one. Wire
`RAVEN_APPLY_HOOK` to your runner (AWX, Ansible Automation Platform, a CI job)
if you want the last hop automated; the hook receives the artefact path and the
approval id and nothing else.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import orjson
import yaml

from raven_common import bus, db, topics
from raven_common.metrics import ERRORS
from raven_common.models import AgentDecision
from raven_common.runtime import bootstrap, run as run_service

SERVICE = "remediation"
settings, log = bootstrap(SERVICE)
ARTEFACTS = Path(os.environ.get("RAVEN_ARTEFACT_DIR", "/artefacts"))
APPLY_HOOK = os.environ.get("RAVEN_APPLY_HOOK", "")


def playbook(name: str, host: str, tasks: list[str]) -> str:
    return yaml.safe_dump([{
        "name": name,
        "hosts": host,
        "become": True,
        "gather_facts": True,
        "any_errors_fatal": True,
        "max_fail_percentage": 0,
        "tasks": [
            {"name": f"step {i + 1}", "ansible.builtin.shell": cmd,
             "register": f"step_{i + 1}", "changed_when": True}
            for i, cmd in enumerate(tasks)
        ],
    }], sort_keys=False)


def write_bundle(decision: AgentDecision) -> dict[str, str]:
    plan = decision.plan
    assert plan is not None
    target = ARTEFACTS / decision.decision_id
    target.mkdir(parents=True, exist_ok=True)
    host = decision.asset_id

    files = {
        "apply.yml": playbook(f"Remediate {plan.cve_id} on {host}", host, plan.patch_commands),
        "validate.yml": playbook(f"Validate {plan.cve_id} on {host}", host, plan.validation),
        "rollback.yml": playbook(f"Roll back {plan.cve_id} on {host}", host, plan.rollback),
        "plan.json": orjson.dumps(plan.model_dump(), option=orjson.OPT_INDENT_2).decode(),
        "README.md": (
            f"# Remediation bundle {decision.decision_id}\n\n"
            f"- CVE: {plan.cve_id}\n- Asset: {plan.asset_id}\n"
            f"- Confidence: {decision.confidence}\n"
            f"- Verifier: {decision.verifier_verdict}\n"
            f"- Estimated downtime: {plan.estimated_downtime_minutes} min\n"
            f"- Reboot required: {plan.requires_reboot}\n\n"
            f"## Summary\n{plan.summary}\n\n"
            f"## Citations\n" + "\n".join(f"- {c}" for c in plan.citations) +
            "\n\n## Order of operations\n"
            "1. `ansible-playbook -C apply.yml` (check mode)\n"
            "2. `ansible-playbook apply.yml`\n"
            "3. `ansible-playbook validate.yml`\n"
            "4. On failure: `ansible-playbook rollback.yml`\n"
        ),
    }
    if plan.iac_patch.strip():
        files["patch.iac.yml"] = plan.iac_patch
    for name, body in files.items():
        (target / name).write_text(body)
    return {name: str(target / name) for name in files}


async def poll_approved(producer: bus.Producer) -> None:
    while True:
        try:
            async with db.conn() as c:
                rows = await c.fetch(
                    """SELECT a.approval_id, a.decision_id, d.*
                       FROM approvals a JOIN agent_decisions d USING (decision_id)
                       WHERE a.state='approved' LIMIT 20"""
                )
            for row in rows:
                d = dict(row)
                plan = d.get("plan")
                if isinstance(plan, (str, bytes)):
                    plan = orjson.loads(plan)
                if not plan:
                    continue
                decision = AgentDecision.model_validate({
                    **{k: v for k, v in d.items() if k in AgentDecision.model_fields},
                    "plan": plan,
                    "decided_at": d["decided_at"],
                })
                paths = await asyncio.to_thread(write_bundle, decision)
                log.info("bundle_written", decision=decision.decision_id, files=len(paths))

                if APPLY_HOOK:
                    code = await asyncio.to_thread(
                        lambda: subprocess.run(
                            [APPLY_HOOK, decision.decision_id, paths["apply.yml"]],
                            capture_output=True, timeout=1800,
                        ).returncode
                    )
                    state = "applied" if code == 0 else "approved"
                    log.info("apply_hook", decision=decision.decision_id, exit=code)
                else:
                    state = "applied"  # artefacts delivered; execution is the operator's step

                async with db.conn() as c:
                    await c.execute(
                        "UPDATE approvals SET state=$2, decided_at=now() WHERE approval_id=$1",
                        d["approval_id"], state,
                    )
                    await c.execute(
                        "INSERT INTO audit_log (actor, action, subject, detail) "
                        "VALUES ($1,$2,$3,$4::jsonb)",
                        "remediation-agent", "bundle_generated",
                        decision.decision_id, orjson.dumps(paths).decode(),
                    )
        except Exception as exc:
            ERRORS.labels(SERVICE, "poll").inc()
            log.warning("remediation_poll_failed", error=str(exc)[:300])
        await asyncio.sleep(15)


async def main() -> None:
    await bus.wait_for_bus()
    ARTEFACTS.mkdir(parents=True, exist_ok=True)
    producer = await bus.Producer(SERVICE).start()

    async def drain() -> None:
        async for decision in bus.consume(
            [topics.REMEDIATIONS], "remediation", AgentDecision, SERVICE
        ):
            log.info("remediation_queued", decision=decision.decision_id,
                     auto=decision.auto_approved)

    await asyncio.gather(drain(), poll_approved(producer))


if __name__ == "__main__":
    run_service(main, SERVICE)

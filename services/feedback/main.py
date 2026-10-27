"""Feedback engine - the closed loop.

Three outputs:

* Model trust score. Brier score against observed outcomes plus the analyst
  override rate, per model and version. A model whose trust falls below the
  floor stops being allowed to produce auto-approvable decisions; the router
  keeps using it for analysis but the autonomy gate refuses it.
* Labelled dataset. Every analyst confirmation, override and remediation
  outcome becomes a training row keyed on (CVE, asset), which is what the GNN
  trainer fine-tunes on.
* Retrain trigger. Once enough new labels accumulate, or structural drift is
  reported, it kicks the trainer.
"""
from __future__ import annotations

import asyncio
import os
import subprocess

import orjson

from raven_common import bus, db, topics
from raven_common.metrics import ERRORS, MODEL_TRUST
from raven_common.models import AgentDecision, FeedbackEvent
from raven_common.runtime import bootstrap, run

SERVICE = "feedback"
settings, log = bootstrap(SERVICE)
RETRAIN_AFTER = int(os.environ.get("RAVEN_RETRAIN_AFTER_LABELS", "200"))
TRUST_FLOOR = float(os.environ.get("RAVEN_MODEL_TRUST_FLOOR", "0.55"))

POSITIVE = {"analyst_confirm", "remediation_success", "missed_exploit"}
NEGATIVE = {"analyst_override", "false_positive", "remediation_failure"}


async def record_label(ev: FeedbackEvent) -> None:
    if not (ev.cve_id and ev.asset_id):
        return
    label = 1.0 if ev.kind in POSITIVE else 0.0
    if ev.kind == "missed_exploit":
        label = 1.0
    async with db.conn() as c:
        row = await c.fetchrow(
            "SELECT components, fused_score, confidence FROM risk_assessments "
            "WHERE cve_id=$1 AND asset_id=$2 ORDER BY scored_at DESC LIMIT 1",
            ev.cve_id, ev.asset_id,
        )
        features = dict(row["components"]) if row and isinstance(row["components"], dict) else {}
        if row:
            features["fused_score"] = float(row["fused_score"])
        await c.execute(
            "INSERT INTO training_examples (cve_id, asset_id, features, label, label_source) "
            "VALUES ($1,$2,$3::jsonb,$4,$5)",
            ev.cve_id, ev.asset_id, orjson.dumps(features).decode(), label, ev.kind,
        )


async def update_trust(ev: FeedbackEvent) -> None:
    if not ev.model_name:
        return
    async with db.conn() as c:
        rows = await c.fetch(
            """SELECT predicted, observed, kind FROM feedback_events
               WHERE model_name=$1 AND model_version=$2
               ORDER BY created_at DESC LIMIT 500""",
            ev.model_name, ev.model_version,
        )
    pairs = [(float(r["predicted"]), float(r["observed"]))
             for r in rows if r["predicted"] is not None and r["observed"] is not None]
    brier = sum((p - o) ** 2 for p, o in pairs) / len(pairs) if pairs else None
    overrides = sum(1 for r in rows if r["kind"] in NEGATIVE)
    override_rate = overrides / len(rows) if rows else 0.0
    trust = max(0.0, min(1.0, 1.0 - (brier if brier is not None else 0.25) - 0.5 * override_rate))

    async with db.conn() as c:
        await c.execute(
            """INSERT INTO model_trust (model_name, model_version, samples, brier,
               override_rate, trust_score, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6, now())
               ON CONFLICT (model_name, model_version) DO UPDATE SET
                 samples=EXCLUDED.samples, brier=EXCLUDED.brier,
                 override_rate=EXCLUDED.override_rate,
                 trust_score=EXCLUDED.trust_score, updated_at=now()""",
            ev.model_name, ev.model_version, len(rows), brier, override_rate, trust,
        )
    MODEL_TRUST.labels(ev.model_name).set(trust)
    if trust < TRUST_FLOOR:
        log.warning("model_trust_below_floor", model=ev.model_name,
                    version=ev.model_version, trust=round(trust, 3))


async def maybe_retrain() -> None:
    while True:
        try:
            async with db.conn() as c:
                pending = await c.fetchval(
                    "SELECT count(*) FROM training_examples WHERE created_at > "
                    "COALESCE((SELECT max(at) FROM audit_log WHERE action='gnn_retrain'), "
                    "now() - interval '30 days')"
                )
            if pending and pending >= RETRAIN_AFTER:
                log.info("retrain_triggered", new_labels=pending)
                code = await asyncio.to_thread(
                    lambda: subprocess.run(
                        ["python", "-m", "train"], cwd="/app", capture_output=True, timeout=7200
                    ).returncode
                )
                async with db.conn() as c:
                    await c.execute(
                        "INSERT INTO audit_log (actor, action, subject, detail) "
                        "VALUES ($1,$2,$3,$4::jsonb)",
                        "feedback-engine", "gnn_retrain", "attackgraph",
                        orjson.dumps({"labels": int(pending), "exit": code}).decode(),
                    )
        except Exception as exc:
            ERRORS.labels(SERVICE, "retrain").inc()
            log.warning("retrain_check_failed", error=str(exc)[:300])
        await asyncio.sleep(1800)


async def main() -> None:
    await bus.wait_for_bus()

    async def consume_feedback() -> None:
        async for ev in bus.consume([topics.FEEDBACK], "feedback", FeedbackEvent, SERVICE):
            try:
                async with db.conn() as c:
                    await c.execute(
                        """INSERT INTO feedback_events (event_id,decision_id,cve_id,asset_id,
                           kind,model_name,model_version,predicted,observed,note,analyst)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                           ON CONFLICT (event_id) DO NOTHING""",
                        ev.event_id, ev.decision_id or None, ev.cve_id or None,
                        ev.asset_id or None, ev.kind, ev.model_name, ev.model_version,
                        ev.predicted, ev.observed, ev.note, ev.analyst,
                    )
                await record_label(ev)
                await update_trust(ev)
                log.info("feedback_recorded", kind=ev.kind, cve=ev.cve_id)
            except Exception as exc:
                ERRORS.labels(SERVICE, "feedback").inc()
                log.warning("feedback_failed", error=str(exc)[:300])

    async def track_decisions() -> None:
        """Every decision is a prediction; park it so outcomes can be scored."""
        async for d in bus.consume(
            [topics.AGENT_DECISIONS], "feedback-decisions", AgentDecision, SERVICE
        ):
            for role, version in (d.model_versions or {}).items():
                MODEL_TRUST.labels(role).set(
                    max(0.0, min(1.0, d.confidence if d.verifier_verdict == "pass" else d.confidence * 0.7))
                )

    await asyncio.gather(consume_feedback(), track_decisions(), maybe_retrain())


if __name__ == "__main__":
    run(main, SERVICE)

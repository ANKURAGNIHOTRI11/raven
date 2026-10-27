"""Risk engine - novel layer 2. Fuses feed, inventory and graph signals into a
single contextual score with a confidence interval and an evidence trail."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import orjson

from raven_common import bus, db, topics
from raven_common.metrics import ERRORS, STAGE_LATENCY
from raven_common.models import Asset, GraphSignal, NormalizedVulnerability, RiskAssessment
from raven_common.runtime import bootstrap, run

from scoring import score

SERVICE = "risk-engine"
settings, log = bootstrap(SERVICE)
SCORER_VERSION = "risk-1.0.0"


async def load_pair(cve_id: str, asset_id: str):
    async with db.conn() as c:
        vrow = await c.fetchrow("SELECT * FROM vulnerabilities WHERE cve_id=$1", cve_id)
        arow = await c.fetchrow("SELECT * FROM assets WHERE asset_id=$1", asset_id)
    if not vrow or not arow:
        return None, None
    v = dict(vrow)
    v["references"] = orjson.loads(v.pop("references_json") or "[]") if isinstance(
        v.get("references_json"), (str, bytes)) else (v.pop("references_json", []) or [])
    return NormalizedVulnerability.model_validate(v), Asset.model_validate(dict(arow))


async def persist(a: RiskAssessment) -> None:
    async with db.conn() as c:
        await c.execute(
            """INSERT INTO risk_assessments (assessment_id,cve_id,asset_id,fused_score,band,
               confidence,ci_low,ci_high,components,evidence,graph_signal,sla_hours,
               scorer_version,scored_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,now())
               ON CONFLICT (assessment_id) DO UPDATE SET
                 fused_score=EXCLUDED.fused_score, band=EXCLUDED.band,
                 confidence=EXCLUDED.confidence, ci_low=EXCLUDED.ci_low,
                 ci_high=EXCLUDED.ci_high, components=EXCLUDED.components,
                 evidence=EXCLUDED.evidence, graph_signal=EXCLUDED.graph_signal,
                 sla_hours=EXCLUDED.sla_hours, scored_at=now()""",
            a.assessment_id, a.cve_id, a.asset_id, a.fused_score, a.band, a.confidence,
            a.ci_low, a.ci_high,
            orjson.dumps(a.components).decode(),
            orjson.dumps([e.model_dump() for e in a.evidence]).decode(),
            orjson.dumps(a.graph_signal.model_dump(mode="json") if a.graph_signal else None).decode(),
            a.sla_hours, a.scorer_version,
        )


async def main() -> None:
    await bus.wait_for_bus()
    producer = await bus.Producer(SERVICE).start()
    async for sig in bus.consume(
        [topics.GRAPH_SIGNALS], "risk-engine", GraphSignal, SERVICE
    ):
        with STAGE_LATENCY.labels(SERVICE, "score").time():
            try:
                vuln, asset = await load_pair(sig.cve_id, sig.asset_id)
                if not vuln or not asset:
                    continue
                s = score(vuln, asset, sig)
                aid = hashlib.sha1(
                    f"{sig.cve_id}:{sig.asset_id}:{SCORER_VERSION}".encode()
                ).hexdigest()[:32]
                assessment = RiskAssessment(
                    assessment_id=aid, cve_id=sig.cve_id, asset_id=sig.asset_id,
                    fused_score=s.score, band=s.band, confidence=s.confidence,
                    ci_low=s.ci_low, ci_high=s.ci_high, components=s.components,
                    evidence=s.evidence, graph_signal=sig, sla_hours=s.sla_hours,
                    scored_at=datetime.now(timezone.utc), scorer_version=SCORER_VERSION,
                )
                await persist(assessment)
                await producer.send(topics.RISK_SCORED, assessment, key=aid)
                if s.band in ("high", "critical") or sig.chain_score > 0.3:
                    await producer.send(topics.AGENT_TASKS, assessment, key=aid)
                log.info("scored", cve=sig.cve_id, asset=sig.asset_id,
                         score=s.score, band=s.band, confidence=s.confidence)
            except Exception as exc:
                ERRORS.labels(SERVICE, "score").inc()
                log.warning("score_failed", cve=sig.cve_id, error=str(exc)[:300])


if __name__ == "__main__":
    run(main, SERVICE)

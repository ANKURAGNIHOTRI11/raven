"""Operator API and console backend.

Authentication is a bearer token by default so the service is never open on
first boot. Put your own SSO in front of it in a real deployment; the token is
the floor, not the ceiling.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import orjson
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, ORJSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import make_asgi_app
from pydantic import BaseModel

from raven_common import bus, db, topics
from raven_common.logging import configure
from raven_common.models import FeedbackEvent
from raven_common.settings import get_settings

settings = get_settings()
log = configure("api", settings.log_level)
API_TOKEN = os.environ.get("RAVEN_API_TOKEN", "change-me")
UI_DIR = Path("/app/ui")

app = FastAPI(title="RAVEN API", version="1.0.0", default_response_class=ORJSONResponse)
app.mount("/metrics", make_asgi_app())
state: dict = {}


@app.on_event("startup")
async def startup() -> None:
    state["producer"] = await bus.Producer("api").start()


@app.on_event("shutdown")
async def shutdown() -> None:
    await state["producer"].stop()


async def auth(authorization: str = Header(default="")) -> str:
    token = authorization.removeprefix("Bearer ").strip()
    if token != API_TOKEN:
        raise HTTPException(401, "invalid or missing bearer token")
    return token


def rows(records) -> list[dict]:
    out = []
    for r in records:
        d = dict(r)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
            elif isinstance(v, (bytes, bytearray)):
                d[k] = orjson.loads(v)
        out.append(d)
    return out


@app.get("/healthz")
async def healthz() -> dict:
    try:
        async with db.conn() as c:
            await c.fetchval("SELECT 1")
        return {"status": "ok"}
    except Exception as exc:
        raise HTTPException(503, str(exc)[:200]) from exc


@app.get("/api/overview")
async def overview(_: str = Depends(auth)) -> dict:
    async with db.conn() as c:
        counts = await c.fetchrow(
            """SELECT
                 (SELECT count(*) FROM vulnerabilities) AS vulnerabilities,
                 (SELECT count(*) FROM assets) AS assets,
                 (SELECT count(*) FROM findings WHERE state='open') AS open_findings,
                 (SELECT count(*) FROM risk_assessments WHERE band IN ('high','critical')) AS elevated,
                 (SELECT count(*) FROM approvals WHERE state='pending') AS pending_approvals,
                 (SELECT count(*) FROM quarantine WHERE NOT reviewed) AS quarantined,
                 (SELECT count(*) FROM graph_signals WHERE chain_score > 0.25) AS chains,
                 (SELECT count(*) FROM agent_decisions WHERE action='abstain') AS abstentions"""
        )
        bands = await c.fetch(
            "SELECT band, count(*) AS n FROM risk_assessments GROUP BY band"
        )
        trust = await c.fetch(
            "SELECT model_name, model_version, trust_score, samples FROM model_trust"
        )
        fresh = await c.fetch(
            "SELECT source_id, last_success, consecutive_failures, circuit_open_until, "
            "accepted_records, quarantined_records FROM sources ORDER BY source_id"
        )
    return {
        "counts": dict(counts),
        "bands": {r["band"]: r["n"] for r in bands},
        "model_trust": rows(trust),
        "sources": rows(fresh),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/findings")
async def findings(
    _: str = Depends(auth),
    limit: int = Query(50, le=500),
    band: str | None = None,
    chains_only: bool = False,
) -> list[dict]:
    clauses, args = [], []
    if band:
        args.append(band)
        clauses.append(f"r.band = ${len(args)}")
    if chains_only:
        clauses.append("COALESCE(g.chain_score, 0) > 0.25")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.append(limit)
    async with db.conn() as c:
        recs = await c.fetch(
            f"""SELECT r.assessment_id, r.cve_id, r.asset_id, r.fused_score, r.band,
                       r.confidence, r.ci_low, r.ci_high, r.sla_hours, r.scored_at,
                       v.severity, v.cvss_base, v.kev, v.epss_percentile, v.exploit_maturity,
                       v.title, a.hostname, a.environment, a.criticality, a.internet_exposed,
                       COALESCE(g.chain_score, 0) AS chain_score,
                       COALESCE(g.blast_radius, 0) AS blast_radius,
                       COALESCE(g.adversarial_flag, false) AS adversarial_flag,
                       d.action, d.confidence AS decision_confidence, d.decision_id
                FROM risk_assessments r
                JOIN vulnerabilities v USING (cve_id)
                JOIN assets a USING (asset_id)
                LEFT JOIN graph_signals g ON g.cve_id = r.cve_id AND g.asset_id = r.asset_id
                LEFT JOIN agent_decisions d ON d.assessment_id = r.assessment_id
                {where}
                ORDER BY r.fused_score DESC, r.scored_at DESC
                LIMIT ${len(args)}""",
            *args,
        )
    return rows(recs)


@app.get("/api/finding/{cve_id}/{asset_id}")
async def finding_detail(cve_id: str, asset_id: str, _: str = Depends(auth)) -> dict:
    async with db.conn() as c:
        assessment = await c.fetchrow(
            "SELECT * FROM risk_assessments WHERE cve_id=$1 AND asset_id=$2 "
            "ORDER BY scored_at DESC LIMIT 1", cve_id, asset_id,
        )
        vuln = await c.fetchrow("SELECT * FROM vulnerabilities WHERE cve_id=$1", cve_id)
        asset = await c.fetchrow("SELECT * FROM assets WHERE asset_id=$1", asset_id)
        decision = await c.fetchrow(
            "SELECT * FROM agent_decisions WHERE cve_id=$1 AND asset_id=$2 "
            "ORDER BY decided_at DESC LIMIT 1", cve_id, asset_id,
        )
        signal = await c.fetchrow(
            "SELECT * FROM graph_signals WHERE cve_id=$1 AND asset_id=$2", cve_id, asset_id,
        )
    if not assessment:
        raise HTTPException(404, "no assessment for that pair")
    out = rows([assessment, vuln, asset])
    return {
        "assessment": out[0],
        "vulnerability": out[1] if vuln else None,
        "asset": out[2] if asset else None,
        "decision": rows([decision])[0] if decision else None,
        "graph_signal": rows([signal])[0] if signal else None,
    }


@app.get("/api/paths")
async def attack_paths(_: str = Depends(auth), limit: int = Query(25, le=200),
                       sleepers_only: bool = False) -> list[dict]:
    async with db.conn() as c:
        recs = await c.fetch(
            "SELECT cve_id, asset_id, chain_score, blast_radius, paths_json, model_version "
            "FROM graph_signals ORDER BY chain_score DESC, blast_radius DESC LIMIT $1",
            limit * 3,
        )
    out = []
    for r in rows(recs):
        paths = r["paths_json"] if isinstance(r["paths_json"], list) else orjson.loads(r["paths_json"] or "[]")
        for p in paths:
            if sleepers_only and not p.get("is_sleeper_chain"):
                continue
            out.append({**p, "cve_id": r["cve_id"], "asset_id": r["asset_id"],
                        "model_version": r["model_version"]})
    out.sort(key=lambda p: p.get("feasibility", 0) * p.get("impact", 0), reverse=True)
    return out[:limit]


@app.get("/api/queue")
async def human_queue(_: str = Depends(auth), limit: int = Query(50, le=200)) -> list[dict]:
    async with db.conn() as c:
        recs = await c.fetch(
            """SELECT ap.approval_id, ap.state, ap.created_at, d.*, r.fused_score, r.band,
                      a.environment, a.hostname, a.criticality
               FROM approvals ap
               JOIN agent_decisions d USING (decision_id)
               JOIN risk_assessments r ON r.assessment_id = d.assessment_id
               JOIN assets a ON a.asset_id = d.asset_id
               WHERE ap.state='pending'
               ORDER BY r.fused_score DESC LIMIT $1""",
            limit,
        )
    return rows(recs)


@app.get("/api/quarantine")
async def quarantine(_: str = Depends(auth), limit: int = Query(50, le=500)) -> list[dict]:
    async with db.conn() as c:
        recs = await c.fetch(
            "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT $1", limit
        )
    return rows(recs)


@app.get("/api/vulnerability/{cve_id}/history")
async def vulnerability_history(
    cve_id: str,
    _: str = Depends(auth),
    limit: int = Query(50, ge=1, le=200),
    after_version: int = Query(0, ge=0),
) -> dict:
    """Read immutable vulnerability snapshots in version order."""
    cve_id = cve_id.strip().upper()

    async with db.conn() as c:
        total = await c.fetchval(
            "SELECT count(*) FROM public.vulnerability_versions WHERE cve_id=$1",
            cve_id,
        )
        if not total:
            raise HTTPException(404, "no history found for vulnerability")

        recs = await c.fetch(
            """SELECT version_id, cve_id, version_no, recorded_at,
                      operation, schema_version, snapshot,
                      snapshot_fingerprint
               FROM public.vulnerability_versions
               WHERE cve_id=$1 AND version_no > $2
               ORDER BY version_no ASC
               LIMIT $3""",
            cve_id, after_version, limit + 1,
        )

    has_more = len(recs) > limit
    items = rows(recs[:limit])

    # asyncpg may return JSONB as text; expose snapshots as JSON objects.
    for item in items:
        snapshot = item.get("snapshot")
        if isinstance(snapshot, (str, bytes, bytearray)):
            item["snapshot"] = orjson.loads(snapshot)

    return {
        "cve_id": cve_id,
        "total_versions": total,
        "returned": len(items),
        "has_more": has_more,
        "next_after_version": (
            items[-1]["version_no"] if has_more and items else None
        ),
        "versions": items,
    }



class ApprovalDecision(BaseModel):
    approve: bool
    analyst: str
    reason: str = ""


@app.post("/api/queue/{approval_id}")
async def decide(approval_id: str, body: ApprovalDecision, _: str = Depends(auth)) -> dict:
    async with db.conn() as c:
        row = await c.fetchrow(
            "SELECT ap.*, d.cve_id, d.asset_id, d.confidence, d.model_versions "
            "FROM approvals ap JOIN agent_decisions d USING (decision_id) "
            "WHERE ap.approval_id=$1", approval_id,
        )
        if not row:
            raise HTTPException(404, "unknown approval")
        if row["state"] != "pending":
            raise HTTPException(409, f"approval already {row['state']}")
        await c.execute(
            "UPDATE approvals SET state=$2, approver=$3, reason=$4, decided_at=now() "
            "WHERE approval_id=$1",
            approval_id, "approved" if body.approve else "rejected", body.analyst, body.reason,
        )
        await c.execute(
            "INSERT INTO audit_log (actor, action, subject, detail) VALUES ($1,$2,$3,$4::jsonb)",
            body.analyst, "approve" if body.approve else "reject", row["decision_id"],
            orjson.dumps({"reason": body.reason}).decode(),
        )

    versions = row["model_versions"] or {}
    if isinstance(versions, (str, bytes)):
        versions = orjson.loads(versions)
    ev = FeedbackEvent(
        event_id=str(uuid.uuid4()),
        decision_id=row["decision_id"], cve_id=row["cve_id"], asset_id=row["asset_id"],
        kind="analyst_confirm" if body.approve else "analyst_override",
        model_name="analyst-llm", model_version=str(versions.get("analyst", "")),
        predicted=float(row["confidence"] or 0.0), observed=1.0 if body.approve else 0.0,
        note=body.reason, analyst=body.analyst,
    )
    await state["producer"].send(topics.FEEDBACK, ev, key=ev.event_id)
    return {"approval_id": approval_id, "state": "approved" if body.approve else "rejected"}


class FeedbackIn(BaseModel):
    kind: str
    cve_id: str = ""
    asset_id: str = ""
    decision_id: str = ""
    analyst: str = ""
    note: str = ""
    predicted: float | None = None
    observed: float | None = None


@app.post("/api/feedback")
async def submit_feedback(body: FeedbackIn, _: str = Depends(auth)) -> dict:
    ev = FeedbackEvent(event_id=str(uuid.uuid4()), **body.model_dump())
    await state["producer"].send(topics.FEEDBACK, ev, key=ev.event_id)
    return {"event_id": ev.event_id, "accepted": True}


if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/")
    async def console() -> FileResponse:
        return FileResponse(UI_DIR / "index.html")

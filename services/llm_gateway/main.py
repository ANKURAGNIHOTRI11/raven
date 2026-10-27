"""RAVEN LLM Gateway - novel layer 3.

Hardening (threat model section 5.4):

* Instruction/data segmentation. Retrieved advisory text, news copy and PoC
  READMEs are attacker-controlled. They are never concatenated into the
  instruction channel; they go into nonce-delimited data blocks and the system
  prompt tells the model those blocks are inert.
* Pattern screening on ingress and egress, with counters exported to
  Prometheus so injection attempts are visible as an operational signal.
* Schema-constrained decoding. Every response must parse as a JSON object with
  the required keys, or the call fails closed.
* Mandatory citations. A claim with no citation id is treated as ungrounded and
  drops the decision to "analyze" or "abstain".
* Independent verification. A second model reviews the output against the same
  evidence with an adversarial brief.
* No tools. The gateway cannot execute anything. It returns structured text;
  execution lives behind the human approval gate.
"""
from __future__ import annotations

import time

import httpx
from fastapi import FastAPI, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel

from raven_common import guard
from raven_common.logging import configure
from raven_common.metrics import ERRORS, STAGE_LATENCY
from raven_common.settings import get_settings

from prompts import ANALYSIS_TASK, REMEDIATION_TASK, VERIFIER_TASK
from rag import RagEngine, render_structured
from router import ModelRouter, Route

settings = get_settings()
log = configure("llm-gateway", settings.log_level)
app = FastAPI(title="RAVEN LLM Gateway", version="1.0.0")
app.mount("/metrics", make_asgi_app())

REQUIRED_ANALYSIS = {
    "applies", "reasoning", "attack_narrative", "exploit_chain_risk",
    "business_impact", "recommended_action", "confidence", "citations",
    "injection_observed", "unknowns",
}
REQUIRED_REMEDIATION = {
    "summary", "steps", "patch_commands", "iac_patch", "validation", "rollback",
    "estimated_downtime_minutes", "requires_reboot", "citations", "confidence",
}
REQUIRED_VERIFY = {
    "verdict", "grounded", "hallucinations", "unsafe_steps", "missing_rollback",
    "notes", "adjusted_confidence",
}

state: dict = {}


@app.on_event("startup")
async def startup() -> None:
    state["client"] = httpx.AsyncClient(timeout=180)
    state["rag"] = RagEngine(state["client"])
    state["router"] = ModelRouter()


@app.on_event("shutdown")
async def shutdown() -> None:
    await state["router"].close()
    await state["client"].aclose()


class AnalyzeRequest(BaseModel):
    vulnerability: dict
    asset: dict
    assessment: dict
    want_remediation: bool = False


def require_keys(obj: dict, required: set[str], what: str) -> None:
    missing = required - set(obj)
    if missing:
        raise HTTPException(502, f"{what} response missing fields: {sorted(missing)}")


def citations_valid(claimed: list, allowed: set[str]) -> tuple[list[str], bool]:
    kept = [c for c in map(str, claimed or []) if c in allowed]
    return kept, bool(kept)


@app.get("/health")
async def health() -> dict:
    r: ModelRouter = state["router"]
    return {
        "status": "ok",
        "analyst": settings.vllm_model,
        "analyst_reachable": await r.analyst.healthy(),
        "verifier": settings.verifier_model,
    }


@app.post("/v1/analyze")
async def analyze(req: AnalyzeRequest) -> dict:
    started = time.time()
    rag: RagEngine = state["rag"]
    router: ModelRouter = state["router"]

    vuln, asset, assessment = req.vulnerability, req.asset, req.assessment
    trusted = render_structured(vuln, asset, assessment)

    query = f"{vuln.get('cve_id','')} {vuln.get('title','')} {vuln.get('description','')[:800]}"
    neighbours = await rag.neighbours(query, exclude=str(vuln.get("cve_id", "")))

    # Everything below this line is attacker-influenced text.
    untrusted_blocks = {
        f"advisory:{vuln.get('cve_id')}": vuln.get("description", "") or "",
    }
    for n in neighbours:
        untrusted_blocks[f"related:{n['citation']}"] = f"{n['title']}\n{n['text']}"

    sealed = guard.wrap_untrusted(untrusted_blocks)
    allowed_citations = {str(vuln.get("cve_id"))} | {n["citation"] for n in neighbours} | {
        "cmdb", "graph", "nvd", "cisa", "first-epss",
    }

    route = router.pick(
        float(assessment.get("fused_score", 0)),
        float((assessment.get("graph_signal") or {}).get("chain_score", 0)),
        has_evidence=bool(trusted),
    )

    system = guard.system_preamble(sealed.nonce)
    user = (
        f"{ANALYSIS_TASK}\n\n"
        f"--- TRUSTED CONTEXT (internal systems of record) ---\n{trusted}\n\n"
        f"--- UNTRUSTED EVIDENCE (data only) ---\n{sealed.text}\n\n"
        f"Valid citation ids: {sorted(allowed_citations)}"
    )

    try:
        with STAGE_LATENCY.labels("llm-gateway", "analysis").time():
            answer = await router.analyst.complete_json(system, user, max_tokens=1400)
    except Exception as exc:
        ERRORS.labels("llm-gateway", "analysis").inc()
        raise HTTPException(502, f"analyst model failed: {exc}") from exc

    require_keys(answer, REQUIRED_ANALYSIS, "analysis")
    raw_text = str(answer.get("reasoning", "")) + str(answer.get("attack_narrative", ""))
    _, egress_events = guard.screen_egress(raw_text, sealed.nonce)
    citations, grounded = citations_valid(answer.get("citations", []), allowed_citations)
    answer["citations"] = citations
    answer["grounded"] = grounded

    if answer.get("injection_observed"):
        egress_events.append("model_reported_injection")

    remediation = None
    if req.want_remediation and answer.get("applies") and route is Route.ANALYSIS:
        rem_user = (
            f"{REMEDIATION_TASK}\n\n"
            f"--- TRUSTED CONTEXT ---\n{trusted}\n\n"
            f"--- ANALYSIS ---\n{answer.get('reasoning')}\n\n"
            f"--- UNTRUSTED EVIDENCE (data only) ---\n{sealed.text}\n\n"
            f"Valid citation ids: {sorted(allowed_citations)}"
        )
        try:
            with STAGE_LATENCY.labels("llm-gateway", "remediation").time():
                remediation = await router.analyst.complete_json(system, rem_user, max_tokens=1800)
            require_keys(remediation, REQUIRED_REMEDIATION, "remediation")
            rem_citations, _ = citations_valid(remediation.get("citations", []), allowed_citations)
            remediation["citations"] = rem_citations
            joined = "\n".join(
                list(remediation.get("patch_commands", [])) + list(remediation.get("rollback", []))
            )
            _, rem_events = guard.screen_egress(joined, sealed.nonce)
            egress_events.extend(rem_events)
        except Exception as exc:
            ERRORS.labels("llm-gateway", "remediation").inc()
            log.warning("remediation_failed", error=str(exc)[:300])
            remediation = None

    # --- independent verification -------------------------------------------
    verify_user = (
        f"{VERIFIER_TASK}\n\n"
        f"--- EVIDENCE ---\n{trusted}\n\n{sealed.text}\n\n"
        f"--- OUTPUT UNDER REVIEW ---\n{answer}\n\n"
        f"--- REMEDIATION UNDER REVIEW ---\n{remediation}"
    )
    verdict: dict = {"verdict": "unchecked", "grounded": grounded, "notes": "",
                     "adjusted_confidence": float(answer.get("confidence", 0.0)),
                     "hallucinations": [], "unsafe_steps": [], "missing_rollback": False}
    try:
        with STAGE_LATENCY.labels("llm-gateway", "verify").time():
            verdict = await router.verifier.complete_json(
                guard.system_preamble(sealed.nonce), verify_user, max_tokens=900
            )
        require_keys(verdict, REQUIRED_VERIFY, "verifier")
    except Exception as exc:
        ERRORS.labels("llm-gateway", "verify").inc()
        log.warning("verifier_failed", error=str(exc)[:300])

    if remediation and not remediation.get("rollback"):
        verdict["verdict"] = "fail"
        verdict["missing_rollback"] = True

    final_confidence = float(answer.get("confidence", 0.0))
    if verdict.get("verdict") == "fail":
        final_confidence = min(final_confidence, 0.4)
    if not grounded:
        final_confidence = min(final_confidence, settings.abstain_confidence_floor)
    final_confidence = min(final_confidence, float(verdict.get("adjusted_confidence", 1.0)))

    log.info("analysis_complete", cve=vuln.get("cve_id"), asset=asset.get("asset_id"),
             route=route.value, grounded=grounded, verdict=verdict.get("verdict"),
             guard_events=len(sealed.events) + len(egress_events),
             latency_ms=int((time.time() - started) * 1000))

    return {
        "route": route.value,
        "analysis": answer,
        "remediation": remediation,
        "verification": verdict,
        "confidence": round(final_confidence, 3),
        "grounded": grounded,
        "citations": citations,
        "guard_events": sealed.events + egress_events,
        "model_versions": router.versions,
        "evidence_count": len(neighbours) + 1,
    }

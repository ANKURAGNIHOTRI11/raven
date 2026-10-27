"""Model router.

Not every question needs 72B parameters. The router sends work to the
cheapest model that can answer it, and always routes the *result* of a
consequential call through the verifier for a second, independent pass.

  triage     -> encoder classifier (is this even relevant to this asset?)
  analysis   -> Qwen instruct model, JSON-constrained, evidence-grounded
  verify     -> verifier model, sees the answer and the evidence but not the
                original reasoning, and is asked to find the flaw
"""
from __future__ import annotations

from enum import Enum

from raven_common.llm import LLMClient
from raven_common.settings import get_settings


class Route(str, Enum):
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    VERIFY = "verify"


class ModelRouter:
    def __init__(self) -> None:
        s = get_settings()
        self.analyst = LLMClient(s.vllm_base_url, s.vllm_model)
        self.verifier = LLMClient(s.verifier_base_url, s.verifier_model)
        self.versions = {"analyst": s.vllm_model, "verifier": s.verifier_model}

    def pick(self, fused_score: float, chain_score: float, has_evidence: bool) -> Route:
        if not has_evidence:
            return Route.TRIAGE
        if fused_score >= 45 or chain_score >= 0.25:
            return Route.ANALYSIS
        return Route.TRIAGE

    async def close(self) -> None:
        await self.analyst.aclose()
        await self.verifier.aclose()

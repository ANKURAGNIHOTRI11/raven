"""Data contracts. These are the schemas enforced at the edge of the bus.

A record that does not validate against the contract never reaches the
ontology - it is routed to the quarantine topic instead (see the
normalization service and docs/threat-model.md section 5.2).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SourceClass(str, Enum):
    AUTHORITATIVE = "authoritative"   # NVD, CISA KEV, vendor PSIRT
    COMMUNITY = "community"           # OSV, GHSA
    MEDIA = "media"                   # news, blogs
    INTERNAL = "internal"             # CMDB, SBOM - trusted, never LLM-instructable


class SourceDescriptor(BaseModel):
    source_id: str
    name: str
    url: str
    source_class: SourceClass
    trust: float = Field(0.5, ge=0.0, le=1.0)
    enabled: bool = True
    parser: str = "json"
    poll_seconds: int = 3600


class RawDocument(BaseModel):
    """Immutable capture of whatever a source returned, byte for byte."""

    doc_id: str
    source_id: str
    source_class: SourceClass
    url: str
    fetched_at: datetime = Field(default_factory=_now)
    content_sha256: str
    content_type: str = "application/json"
    object_key: str                      # MinIO WORM location
    payload: dict[str, Any] | None = None
    trust: float = 0.5


class Reference(BaseModel):
    url: str
    tags: list[str] = []


_SEVERITY_ALIASES = {
    "important": "high",
    "moderate": "medium",
    "negligible": "low",
    "informational": "low",
    "info": "low",
    "unknown": "none",
    "unspecified": "none",
    "": "none",
}


class NormalizedVulnerability(BaseModel):
    """Canonical CVE record after normalization, dedup and enrichment."""

    cve_id: str
    title: str = ""
    description: str = ""
    published: datetime | None = None
    modified: datetime | None = None

    cvss_vector: str | None = None
    cvss_base: float = Field(0.0, ge=0.0, le=10.0)
    cvss_version: str = "3.1"
    severity: Literal["none", "low", "medium", "high", "critical"] = "none"

    cwe_ids: list[str] = []
    capec_ids: list[str] = []
    attack_techniques: list[str] = []
    cpe_uris: list[str] = []
    affected_packages: list[str] = []
    vendor_advisories: list[str] = []
    references: list[Reference] = []

    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(0.0, ge=0.0, le=1.0)
    kev: bool = False
    kev_due_date: datetime | None = None
    exploit_maturity: Literal["none", "poc", "functional", "weaponized"] = "none"

    provenance: list[str] = []            # doc_ids that contributed
    source_trust: float = 0.5
    ingest_confidence: float = Field(1.0, ge=0.0, le=1.0)
    normalized_at: datetime = Field(default_factory=_now)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v):
        if v is None:
            return "none"
        s = str(v).strip().lower()
        return _SEVERITY_ALIASES.get(s, s)

    @field_validator("cve_id")
    @classmethod
    def _cve_shape(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith(("CVE-", "GHSA-", "RHSA-", "OSV-")):
            raise ValueError(f"unrecognised vulnerability identifier: {v}")
        return v


class Asset(BaseModel):
    """A thing worth defending, from the CMDB/SBOM side of the house."""

    asset_id: str
    hostname: str = ""
    kind: str = "host"                   # host | container | service | dataset
    environment: Literal["prod", "staging", "dev", "lab"] = "prod"
    criticality: int = Field(3, ge=1, le=5)
    internet_exposed: bool = False
    owner: str = ""
    zone: str = "default"
    cpe_uris: list[str] = []
    packages: list[str] = []
    compensating_controls: list[str] = []  # waf, edr, segmentation, ...
    connects_to: list[str] = []            # downstream asset_ids
    updated_at: datetime = Field(default_factory=_now)


class QuarantineRecord(BaseModel):
    doc_id: str
    source_id: str
    reason: str
    detail: str = ""
    severity: Literal["warn", "reject"] = "reject"
    raw_excerpt: str = ""
    quarantined_at: datetime = Field(default_factory=_now)


class AttackPath(BaseModel):
    path_id: str
    nodes: list[str]                     # alternating asset/cve identifiers
    entry_point: str
    target_asset: str
    target_criticality: int = 3
    hops: int = 1
    feasibility: float = Field(0.0, ge=0.0, le=1.0)
    impact: float = Field(0.0, ge=0.0, le=1.0)
    chain_cves: list[str] = []
    is_sleeper_chain: bool = False       # all links low severity, path is not
    explanation: str = ""


class GraphSignal(BaseModel):
    """What the GNN hands to the risk engine for one CVE/asset pairing."""

    cve_id: str
    asset_id: str
    blast_radius: int = 0
    reachability: float = Field(0.0, ge=0.0, le=1.0)
    chain_score: float = Field(0.0, ge=0.0, le=1.0)
    centrality: float = 0.0
    paths: list[AttackPath] = []
    model_version: str = "gnn-0"
    adversarial_flag: bool = False
    computed_at: datetime = Field(default_factory=_now)


class EvidenceItem(BaseModel):
    kind: str                            # feed | graph | model | control
    label: str
    value: str
    weight: float = 0.0
    source: str = ""


class RiskAssessment(BaseModel):
    assessment_id: str
    cve_id: str
    asset_id: str
    fused_score: float = Field(0.0, ge=0.0, le=100.0)
    band: Literal["informational", "low", "medium", "high", "critical"] = "low"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    ci_low: float = 0.0
    ci_high: float = 0.0
    components: dict[str, float] = {}
    evidence: list[EvidenceItem] = []
    graph_signal: GraphSignal | None = None
    sla_hours: int = 720
    scored_at: datetime = Field(default_factory=_now)
    scorer_version: str = "risk-1.0.0"


class AgentAction(str, Enum):
    ABSTAIN = "abstain"
    ANALYZE = "analyze"
    ACT = "act"


class RemediationPlan(BaseModel):
    plan_id: str
    cve_id: str
    asset_id: str
    summary: str
    steps: list[str] = []
    patch_commands: list[str] = []
    iac_patch: str = ""
    validation: list[str] = []
    rollback: list[str] = []             # mandatory, gate rejects empty
    estimated_downtime_minutes: int = 0
    requires_reboot: bool = False
    citations: list[str] = []


class AgentDecision(BaseModel):
    decision_id: str
    assessment_id: str
    cve_id: str
    asset_id: str
    action: AgentAction
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    rationale: str = ""
    verifier_verdict: Literal["pass", "fail", "unchecked"] = "unchecked"
    verifier_notes: str = ""
    grounded: bool = False
    citations: list[str] = []
    plan: RemediationPlan | None = None
    blast_radius: int = 0
    auto_approved: bool = False
    guard_events: list[str] = []
    model_versions: dict[str, str] = {}
    decided_at: datetime = Field(default_factory=_now)


class FeedbackEvent(BaseModel):
    event_id: str
    decision_id: str = ""
    cve_id: str = ""
    asset_id: str = ""
    kind: Literal[
        "analyst_override", "analyst_confirm", "remediation_success",
        "remediation_failure", "false_positive", "missed_exploit",
    ]
    model_name: str = ""
    model_version: str = ""
    predicted: float | None = None
    observed: float | None = None
    note: str = ""
    analyst: str = ""
    created_at: datetime = Field(default_factory=_now)

"""Fused risk scoring.

The output is deliberately not another 0-10 severity. It is an
organisation-specific 0-100 exposure score with an explicit confidence
interval and a full evidence trail, because the thing an operator needs is not
"how bad is this bug" but "how bad is this bug, here, today, given what we
already have in front of it".

    fused = 100 * sigma( w . features )

Weights are held in one place so they can be tuned against outcome data by the
feedback engine rather than argued about in a meeting.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from raven_common.models import Asset, EvidenceItem, GraphSignal, NormalizedVulnerability

WEIGHTS = {
    "cvss": 1.35,
    "epss": 1.75,
    "kev": 2.30,
    "maturity": 0.95,
    "criticality": 1.60,
    "exposure": 1.20,
    "reachability": 1.45,
    "blast": 1.05,
    "chain": 1.90,          # the chain term outranks raw CVSS by design
    "controls": -1.50,
    "nonprod": -0.85,
    "stale_intel": -0.40,
}
BIAS = -4.2

MATURITY = {"none": 0.0, "poc": 0.4, "functional": 0.75, "weaponized": 1.0}
CONTROL_STRENGTH = {
    "waf": 0.30, "edr": 0.35, "segmentation": 0.40, "mfa": 0.25,
    "ips": 0.30, "allowlist": 0.35, "offline": 0.60, "vpn_only": 0.30,
}
BANDS = [(85, "critical", 24), (70, "high", 72), (45, "medium", 336), (20, "low", 720)]


@dataclass
class Scored:
    score: float
    band: str
    sla_hours: int
    confidence: float
    ci_low: float
    ci_high: float
    components: dict[str, float]
    evidence: list[EvidenceItem]


def control_factor(controls: list[str]) -> float:
    """Diminishing returns: three overlapping controls are not three times one."""
    remaining = 1.0
    for c in controls:
        remaining *= (1.0 - CONTROL_STRENGTH.get(c.lower(), 0.10))
    return 1.0 - remaining


def score(v: NormalizedVulnerability, a: Asset, g: GraphSignal | None) -> Scored:
    g = g or GraphSignal(cve_id=v.cve_id, asset_id=a.asset_id)
    ctrl = control_factor(a.compensating_controls)

    feats = {
        "cvss": v.cvss_base / 10.0,
        "epss": v.epss_percentile,
        "kev": 1.0 if v.kev else 0.0,
        "maturity": MATURITY.get(v.exploit_maturity, 0.0),
        "criticality": (a.criticality - 1) / 4.0,
        "exposure": 1.0 if a.internet_exposed else 0.0,
        "reachability": g.reachability,
        "blast": min(g.blast_radius, 20) / 20.0,
        "chain": g.chain_score,
        "controls": ctrl,
        "nonprod": 0.0 if a.environment == "prod" else 1.0,
        "stale_intel": 1.0 - v.source_trust,
    }
    z = BIAS + sum(WEIGHTS[k] * val for k, val in feats.items())
    fused = 100.0 / (1.0 + math.exp(-z))

    # Confidence: how much of the score rests on data we actually have.
    have = [
        v.cvss_base > 0, v.epss_percentile > 0, bool(v.cpe_uris or v.affected_packages),
        g.reachability > 0, a.criticality > 0, v.source_trust >= 0.8,
    ]
    coverage = sum(have) / len(have)
    confidence = round(max(0.05, min(0.99, 0.35 * coverage + 0.45 * v.ingest_confidence
                                     + 0.20 * v.source_trust)), 3)
    if g.adversarial_flag:
        confidence = round(confidence * 0.55, 3)

    spread = (1.0 - confidence) * 28.0
    ci_low, ci_high = max(0.0, fused - spread), min(100.0, fused + spread)

    band, sla = "informational", 2160
    for threshold, name, hours in BANDS:
        if fused >= threshold:
            band, sla = name, hours
            break
    if v.kev and v.kev_due_date:
        sla = min(sla, 72)

    evidence = [
        EvidenceItem(kind="feed", label="CVSS base", value=f"{v.cvss_base:.1f} ({v.cvss_version})",
                     weight=WEIGHTS["cvss"] * feats["cvss"], source="nvd"),
        EvidenceItem(kind="feed", label="EPSS percentile", value=f"{v.epss_percentile:.3f}",
                     weight=WEIGHTS["epss"] * feats["epss"], source="first-epss"),
        EvidenceItem(kind="feed", label="CISA KEV", value="listed" if v.kev else "not listed",
                     weight=WEIGHTS["kev"] * feats["kev"], source="cisa"),
        EvidenceItem(kind="feed", label="Exploit maturity", value=v.exploit_maturity,
                     weight=WEIGHTS["maturity"] * feats["maturity"], source="normalizer"),
        EvidenceItem(kind="control", label="Asset criticality", value=f"{a.criticality}/5",
                     weight=WEIGHTS["criticality"] * feats["criticality"], source="cmdb"),
        EvidenceItem(kind="control", label="Internet exposed", value=str(a.internet_exposed),
                     weight=WEIGHTS["exposure"] * feats["exposure"], source="cmdb"),
        EvidenceItem(kind="graph", label="Attack-path reachability", value=f"{g.reachability:.3f}",
                     weight=WEIGHTS["reachability"] * feats["reachability"], source=g.model_version),
        EvidenceItem(kind="graph", label="Blast radius", value=f"{g.blast_radius} assets",
                     weight=WEIGHTS["blast"] * feats["blast"], source=g.model_version),
        EvidenceItem(kind="graph", label="Exploit-chain score", value=f"{g.chain_score:.3f}",
                     weight=WEIGHTS["chain"] * feats["chain"], source=g.model_version),
        EvidenceItem(kind="control", label="Compensating controls",
                     value=", ".join(a.compensating_controls) or "none",
                     weight=WEIGHTS["controls"] * feats["controls"], source="cmdb"),
        EvidenceItem(kind="control", label="Environment", value=a.environment,
                     weight=WEIGHTS["nonprod"] * feats["nonprod"], source="cmdb"),
    ]
    if any(p.is_sleeper_chain for p in g.paths):
        top = next(p for p in g.paths if p.is_sleeper_chain)
        evidence.append(EvidenceItem(
            kind="graph", label="Sleeper chain",
            value=f"{' -> '.join(top.nodes[:6])} ({top.hops} hops)",
            weight=WEIGHTS["chain"] * feats["chain"], source=g.model_version,
        ))
    if g.adversarial_flag:
        evidence.append(EvidenceItem(
            kind="model", label="Robustness", value="graph signal flagged unstable or drifted",
            weight=0.0, source="adversarial-monitor",
        ))

    return Scored(
        score=round(fused, 2), band=band, sla_hours=sla, confidence=confidence,
        ci_low=round(ci_low, 2), ci_high=round(ci_high, 2),
        components={k: round(WEIGHTS[k] * val, 4) for k, val in feats.items()},
        evidence=evidence,
    )

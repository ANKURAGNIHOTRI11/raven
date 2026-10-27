"""Evidence-grounded retrieval.

Every fact the analyst model is allowed to assert has to trace back to a
retrieved chunk with a citation id. Retrieval pulls from three places:

  * Qdrant  - semantic neighbours of the CVE text (other advisories, prior
              incidents, vendor notes)
  * Postgres- the structured record: scores, KEV state, affected packages
  * Neo4j   - the graph context the GNN produced, rendered as text

The structured sources are trusted; the Qdrant chunks are attacker-influenced
and are wrapped by the prompt guard before they go anywhere near the model.
"""
from __future__ import annotations

import httpx

from raven_common.settings import get_settings

settings = get_settings()


class RagEngine:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def embed(self, text: str) -> list[float] | None:
        try:
            r = await self.client.post(
                "http://embedder:8080/embed", json={"texts": [text]}, timeout=60
            )
            return r.json()["embeddings"][0]
        except Exception:
            return None

    async def neighbours(self, text: str, limit: int = 6, exclude: str = "") -> list[dict]:
        vector = await self.embed(text)
        if vector is None:
            return []
        try:
            r = await self.client.post(
                f"{settings.qdrant_url}/collections/raven_vulns/points/search",
                json={"vector": vector, "limit": limit + 1, "with_payload": True},
                timeout=30,
            )
            hits = r.json().get("result", [])
        except Exception:
            return []
        out = []
        for h in hits:
            payload = h.get("payload", {})
            if payload.get("cve_id") == exclude:
                continue
            out.append({
                "citation": payload.get("citation") or payload.get("cve_id", "unknown"),
                "cve_id": payload.get("cve_id", ""),
                "title": payload.get("title", ""),
                "text": (payload.get("text") or "")[:1200],
                "score": round(float(h.get("score", 0.0)), 4),
            })
        return out[:limit]


def render_structured(vuln: dict, asset: dict, assessment: dict) -> str:
    """Trusted context. Goes in the instruction channel, not a data block."""
    paths = ""
    sig = (assessment or {}).get("graph_signal") or {}
    for p in (sig.get("paths") or [])[:3]:
        marker = " [sleeper chain]" if p.get("is_sleeper_chain") else ""
        paths += f"\n  - {' -> '.join(p.get('nodes', [])[:8])} (feasibility {p.get('feasibility')}, {p.get('hops')} hops){marker}"
    return (
        f"VULNERABILITY {vuln.get('cve_id')}\n"
        f"  CVSS {vuln.get('cvss_base')} {vuln.get('cvss_vector') or ''} | severity {vuln.get('severity')}\n"
        f"  EPSS percentile {vuln.get('epss_percentile')} | CISA KEV: {vuln.get('kev')}\n"
        f"  exploit maturity: {vuln.get('exploit_maturity')} | CWE: {', '.join(vuln.get('cwe_ids') or []) or 'none'}\n"
        f"  affected packages: {', '.join((vuln.get('affected_packages') or [])[:12]) or 'unknown'}\n"
        f"ASSET {asset.get('asset_id')} ({asset.get('hostname')})\n"
        f"  kind {asset.get('kind')} | environment {asset.get('environment')} | criticality {asset.get('criticality')}/5\n"
        f"  internet exposed: {asset.get('internet_exposed')} | zone {asset.get('zone')}\n"
        f"  installed: {', '.join((asset.get('packages') or [])[:15]) or 'unknown'}\n"
        f"  compensating controls: {', '.join(asset.get('compensating_controls') or []) or 'none'}\n"
        f"GRAPH SIGNAL (model {sig.get('model_version','n/a')})\n"
        f"  reachability {sig.get('reachability', 0)} | blast radius {sig.get('blast_radius', 0)} assets"
        f" | chain score {sig.get('chain_score', 0)}{paths or ' | no ranked path'}\n"
        f"FUSED RISK {assessment.get('fused_score')} ({assessment.get('band')}), "
        f"confidence {assessment.get('confidence')} "
        f"[{assessment.get('ci_low')}-{assessment.get('ci_high')}]"
    )

"""GNN engine service - novel layer 1.

Responsibilities
----------------
* Maintain a live tensor snapshot of the Neo4j attack graph.
* Score every edge for exploitability and every node for blast radius.
* Rank attack paths from internet-exposed entry points to crown-jewel assets.
* Flag sleeper chains: combinations of individually low-severity CVEs that
  together open a path to a critical asset.
* Run the adversarial-robustness monitor over both the input graph and the
  model weights, and mark any signal it cannot vouch for.
* Emit one GraphSignal per (CVE, asset) finding for the risk engine.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import orjson
import torch
from neo4j import AsyncGraphDatabase

from raven_common import bus, db, topics
from raven_common.metrics import ERRORS, MODEL_TRUST, STAGE_LATENCY
from raven_common.models import AttackPath, GraphSignal, NormalizedVulnerability
from raven_common.runtime import bootstrap, run

from chains import build_adjacency, score_paths, sleeper_chains
from graphio import load_snapshot
from model import AttackGraphNet, ModelConfig
from robustness import (
    StructuralBaseline, instability_summary, smoothing_instability, weight_fingerprint,
)

SERVICE = "gnn-engine"
settings, log = bootstrap(SERVICE)
CKPT_DIR = Path(os.environ.get("RAVEN_GNN_CKPT_DIR", "/models/gnn"))
RECOMPUTE_SECONDS = int(os.environ.get("RAVEN_GNN_RECOMPUTE_SECONDS", "300"))
baseline = StructuralBaseline()


def load_model(dev: str) -> tuple[AttackGraphNet, str, bool]:
    """Returns (model, fingerprint, tamper_flag)."""
    model = AttackGraphNet(ModelConfig()).to(dev)
    ckpt = CKPT_DIR / "attackgraph.pt"
    tampered = False
    if ckpt.exists():
        model.load_state_dict(torch.load(ckpt, map_location=dev))
        fp = weight_fingerprint(model)
        recorded = CKPT_DIR / "fingerprint.json"
        if recorded.exists():
            expected = json.loads(recorded.read_text()).get("fingerprint")
            if expected and expected != fp:
                tampered = True
                log.error("weight_tamper_detected", expected=expected[:16], actual=fp[:16])
    else:
        fp = weight_fingerprint(model)
        log.warning("cold_start_model", note="untrained weights; run the trainer")
    model.eval()
    return model, fp, tampered


async def open_findings() -> list[tuple[str, str]]:
    async with db.conn() as c:
        rows = await c.fetch(
            "SELECT cve_id, asset_id FROM findings WHERE state='open' "
            "ORDER BY last_seen DESC LIMIT 20000"
        )
    return [(r["cve_id"], r["asset_id"]) for r in rows]


async def persist_signal(sig: GraphSignal) -> None:
    async with db.conn() as c:
        await c.execute(
            """INSERT INTO graph_signals (cve_id, asset_id, blast_radius, reachability,
               chain_score, centrality, paths_json, model_version, adversarial_flag, computed_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9, now())
               ON CONFLICT (cve_id, asset_id) DO UPDATE SET
                 blast_radius=EXCLUDED.blast_radius, reachability=EXCLUDED.reachability,
                 chain_score=EXCLUDED.chain_score, centrality=EXCLUDED.centrality,
                 paths_json=EXCLUDED.paths_json, model_version=EXCLUDED.model_version,
                 adversarial_flag=EXCLUDED.adversarial_flag, computed_at=now()""",
            sig.cve_id, sig.asset_id, sig.blast_radius, sig.reachability, sig.chain_score,
            sig.centrality, orjson.dumps([p.model_dump(mode="json") for p in sig.paths]).decode(),
            sig.model_version, sig.adversarial_flag,
        )


async def recompute(driver, producer: bus.Producer) -> None:
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    with STAGE_LATENCY.labels(SERVICE, "snapshot").time():
        snap = await load_snapshot(driver, dev)
    if snap.num_nodes < 2:
        log.info("graph_empty")
        return

    model, fingerprint, tampered = load_model(dev)
    with STAGE_LATENCY.labels(SERVICE, "inference").time(), torch.no_grad():
        out = model(snap.x, snap.edge_index)
    edge_w = out["edge_exploitability"].detach().to("cpu")
    impacts = out["impact"].detach().to("cpu")

    # --- adversarial monitor -------------------------------------------------
    mean_degree = float(snap.edge_index.size(1)) / max(snap.num_nodes, 1)
    drift, reasons = baseline.drift(snap.kinds, mean_degree)
    baseline.update(snap.kinds, mean_degree)
    std = smoothing_instability(model, snap.x, snap.edge_index)
    unstable_count, mean_std = instability_summary(std)
    unstable = set((std > 0.08).nonzero().flatten().tolist())
    suspect = tampered or drift > 0.5
    MODEL_TRUST.labels("gnn").set(max(0.0, 1.0 - mean_std * 4 - (0.5 if suspect else 0.0)))
    if reasons:
        log.warning("graph_drift", drift=round(drift, 3), reasons=reasons[:5])

    # --- path search ---------------------------------------------------------
    with STAGE_LATENCY.labels(SERVICE, "paths").time():
        adj = build_adjacency(snap, edge_w.tolist())
        paths = score_paths(snap, adj, impacts.tolist())
        sleepers = {p.path_id for p in sleeper_chains(snap, paths)}

    by_node: dict[str, list] = {}
    for p in paths:
        for key in p.nodes:
            by_node.setdefault(key, []).append(p)

    degree: dict[int, int] = {}
    for a in snap.edge_index[0].tolist():
        degree[a] = degree.get(a, 0) + 1
    max_degree = max(degree.values()) if degree else 1

    version = f"gnn-{fingerprint[:12]}"
    emitted = 0
    for cve_id, asset_id in await open_findings():
        idx_c, idx_a = snap.index.get(cve_id), snap.index.get(asset_id)
        if idx_c is None or idx_a is None:
            continue
        relevant = [p for p in by_node.get(cve_id, []) if asset_id in p.nodes] or by_node.get(cve_id, [])[:3]
        best = max(relevant, key=lambda p: p.risk, default=None)
        chain = max(
            (p.risk for p in relevant if p.path_id in sleepers), default=0.0
        )
        blast = len({n for p in relevant for n in p.nodes
                     if snap.kinds[snap.index[n]] == "asset"}) if relevant else 1
        sig = GraphSignal(
            cve_id=cve_id,
            asset_id=asset_id,
            blast_radius=blast,
            reachability=round(best.feasibility if best else float(edge_w.mean()), 4),
            chain_score=round(chain, 4),
            centrality=round(degree.get(idx_c, 0) / max_degree, 4),
            model_version=version,
            adversarial_flag=suspect or idx_c in unstable or idx_a in unstable,
            paths=[
                AttackPath(
                    path_id=p.path_id, nodes=p.nodes, entry_point=p.nodes[0],
                    target_asset=p.nodes[-1],
                    target_criticality=int(snap.meta.get(p.nodes[-1], {}).get("criticality", 3) or 3),
                    hops=p.hops, feasibility=p.feasibility, impact=p.impact,
                    chain_cves=p.cves, is_sleeper_chain=p.path_id in sleepers,
                    explanation=(
                        f"{p.hops} hops from {p.nodes[0]} to {p.nodes[-1]} via "
                        f"{len(p.cves)} vulnerabilities"
                        + (" - all links below escalation severity" if p.path_id in sleepers else "")
                    ),
                )
                for p in sorted(relevant, key=lambda p: p.risk, reverse=True)[:5]
            ],
        )
        await persist_signal(sig)
        await producer.send(topics.GRAPH_SIGNALS, sig, key=f"{cve_id}:{asset_id}")
        emitted += 1

    log.info("recompute_done", nodes=snap.num_nodes, edges=int(snap.edge_index.size(1)),
             paths=len(paths), sleeper_chains=len(sleepers), signals=emitted,
             unstable_nodes=unstable_count, tampered=tampered, device=dev)


async def main() -> None:
    await bus.wait_for_bus()
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    for _ in range(60):
        try:
            await driver.verify_connectivity()
            break
        except Exception:
            await asyncio.sleep(2)
    producer = await bus.Producer(SERVICE).start()
    dirty = asyncio.Event()

    async def watch() -> None:
        async for _ in bus.consume(
            [topics.GRAPH_UPDATES], "gnn-trigger", NormalizedVulnerability, SERVICE
        ):
            dirty.set()

    async def loop() -> None:
        while True:
            try:
                await recompute(driver, producer)
            except Exception as exc:
                ERRORS.labels(SERVICE, "recompute").inc()
                log.warning("recompute_failed", error=str(exc)[:400])
            dirty.clear()
            try:
                await asyncio.wait_for(dirty.wait(), timeout=RECOMPUTE_SECONDS)
                await asyncio.sleep(20)  # coalesce bursts of graph updates
            except asyncio.TimeoutError:
                pass

    await asyncio.gather(watch(), loop())


if __name__ == "__main__":
    run(main, SERVICE)

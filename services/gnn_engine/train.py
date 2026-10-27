"""Training / retraining for the attack-graph network.

Two objectives are combined:

1. Self-supervised link prediction on the live graph. Positive edges are real
   relations; negatives are sampled non-edges. This teaches the encoder the
   topology of the estate without needing labels, which matters because nobody
   has a labelled corpus of their own breaches.
2. Supervised fine-tuning on `training_examples` produced by the feedback
   engine - analyst confirmations, real exploitation events, remediation
   outcomes. This is the loop that makes the ranking match the organisation
   rather than a generic prior.

Runs on the H200 in fp32 with TF32 matmuls enabled; the graph is small enough
that mixed precision buys little and costs numerical headroom in the path
scores.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import torch
import torch.nn.functional as F
from neo4j import AsyncGraphDatabase

from raven_common.db import conn
from raven_common.runtime import bootstrap

from graphio import load_snapshot
from model import AttackGraphNet, ModelConfig
from robustness import weight_fingerprint

SERVICE = "gnn-trainer"
settings, log = bootstrap(SERVICE)
CKPT_DIR = Path(os.environ.get("RAVEN_GNN_CKPT_DIR", "/models/gnn"))


def device() -> str:
    return "cuda" if torch.cuda.is_available() else "cpu"


def sample_negatives(num_nodes: int, count: int, dev: str) -> torch.Tensor:
    return torch.randint(0, max(num_nodes, 1), (2, count), device=dev)


async def supervised_batch(index: dict[str, int], dev: str):
    async with conn() as c:
        rows = await c.fetch(
            "SELECT cve_id, asset_id, label FROM training_examples "
            "ORDER BY created_at DESC LIMIT 20000"
        )
    pairs, labels = [], []
    for r in rows:
        a, b = index.get(r["asset_id"]), index.get(r["cve_id"])
        if a is None or b is None:
            continue
        pairs.append([a, b])
        labels.append(float(r["label"]))
    if not pairs:
        return None, None
    return (
        torch.tensor(pairs, dtype=torch.long, device=dev).t(),
        torch.tensor(labels, dtype=torch.float32, device=dev),
    )


async def train(epochs: int = 300, lr: float = 2e-3) -> dict:
    dev = device()
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    snap = await load_snapshot(driver, dev)
    await driver.close()
    if snap.edge_index.size(1) < 8:
        log.warning("graph_too_small_to_train", edges=int(snap.edge_index.size(1)))
        return {"trained": False}

    model = AttackGraphNet(ModelConfig()).to(dev)
    ckpt = CKPT_DIR / "attackgraph.pt"
    if ckpt.exists():
        try:
            model.load_state_dict(torch.load(ckpt, map_location=dev))
            log.info("warm_start", checkpoint=str(ckpt))
        except Exception as exc:
            log.warning("warm_start_failed", error=str(exc)[:200])

    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    sup_edges, sup_labels = await supervised_batch(snap.index, dev)

    pos = snap.edge_index
    model.train()
    last = {}
    for epoch in range(epochs):
        opt.zero_grad(set_to_none=True)
        h = model.encode(snap.x, snap.edge_index)

        neg = sample_negatives(snap.num_nodes, pos.size(1), dev)
        pos_score = model.edge_scores(h, pos)
        neg_score = model.edge_scores(h, neg)
        link_loss = (
            F.binary_cross_entropy(pos_score.clamp(1e-6, 1 - 1e-6), torch.ones_like(pos_score))
            + F.binary_cross_entropy(neg_score.clamp(1e-6, 1 - 1e-6), torch.zeros_like(neg_score))
        )

        # Impact head is anchored to recorded asset criticality so the learned
        # blast radius stays calibrated against the CMDB.
        crit = snap.x[:, -6]  # criticality slot from featurize()
        impact_loss = F.mse_loss(model.node_impact(h), crit)

        loss = link_loss + 0.5 * impact_loss
        if sup_edges is not None:
            sup_pred = model.edge_scores(h, sup_edges)
            loss = loss + 1.5 * F.binary_cross_entropy(
                sup_pred.clamp(1e-6, 1 - 1e-6), sup_labels.clamp(0, 1)
            )

        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        sched.step()
        if epoch % 50 == 0:
            log.info("epoch", epoch=epoch, loss=round(float(loss), 4),
                     link=round(float(link_loss), 4))
        last = {"loss": float(loss), "link_loss": float(link_loss)}

    CKPT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), ckpt)
    fp = weight_fingerprint(model)
    (CKPT_DIR / "fingerprint.json").write_text(json.dumps({
        "fingerprint": fp, "nodes": snap.num_nodes,
        "edges": int(snap.edge_index.size(1)), "metrics": last,
        "supervised_pairs": 0 if sup_edges is None else int(sup_edges.size(1)),
    }, indent=2))
    log.info("training_complete", fingerprint=fp[:16], **last)
    return {"trained": True, "fingerprint": fp, **last}


if __name__ == "__main__":
    asyncio.run(train(epochs=int(os.environ.get("RAVEN_GNN_EPOCHS", "300"))))

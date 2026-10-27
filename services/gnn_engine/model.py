"""RAVEN attack-graph neural network.

Design notes
------------
The graph is heterogeneous in meaning but homogeneous in storage: every node
(asset, vulnerability, weakness, attack pattern, technique, zone) is a row in
one feature matrix with a type one-hot prefix. That keeps the encoder simple
enough to retrain nightly on a single H200 while still letting message passing
carry attacker semantics across node kinds.

Three heads sit on the shared encoder:

* ``exploitability`` - probability an attacker can traverse an edge.
  Used as the edge weight for attack-path search.
* ``chain`` - probability that a *set* of individually unremarkable
  vulnerabilities composes into a path to a critical asset. This is the
  exploit-chain predictor; it is trained on the path level, not the CVE level,
  which is why it can flag combinations that per-CVE scoring misses.
* ``impact`` - expected blast radius if the node is compromised.
"""
from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn.functional as F
from torch import Tensor, nn
from torch_geometric.nn import GATv2Conv, SAGEConv

NODE_TYPES = ["asset", "vulnerability", "cwe", "attack_pattern", "technique", "zone"]
NUM_TYPES = len(NODE_TYPES)
NUM_NUMERIC = 10           # see featurize() in graphio.py
IN_DIM = NUM_TYPES + NUM_NUMERIC


@dataclass
class ModelConfig:
    hidden: int = 256
    layers: int = 3
    heads: int = 4
    dropout: float = 0.2


class AttackGraphNet(nn.Module):
    def __init__(self, cfg: ModelConfig | None = None) -> None:
        super().__init__()
        cfg = cfg or ModelConfig()
        self.cfg = cfg
        self.input = nn.Linear(IN_DIM, cfg.hidden)
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        for i in range(cfg.layers):
            if i % 2 == 0:
                self.convs.append(
                    GATv2Conv(cfg.hidden, cfg.hidden // cfg.heads, heads=cfg.heads,
                              dropout=cfg.dropout, add_self_loops=True)
                )
            else:
                self.convs.append(SAGEConv(cfg.hidden, cfg.hidden))
            self.norms.append(nn.LayerNorm(cfg.hidden))

        self.exploitability = nn.Sequential(
            nn.Linear(cfg.hidden * 2, cfg.hidden), nn.GELU(),
            nn.Dropout(cfg.dropout), nn.Linear(cfg.hidden, 1),
        )
        self.chain = nn.Sequential(
            nn.Linear(cfg.hidden * 3, cfg.hidden), nn.GELU(),
            nn.Dropout(cfg.dropout), nn.Linear(cfg.hidden, 1),
        )
        self.impact = nn.Sequential(
            nn.Linear(cfg.hidden, cfg.hidden // 2), nn.GELU(),
            nn.Linear(cfg.hidden // 2, 1),
        )

    def encode(self, x: Tensor, edge_index: Tensor) -> Tensor:
        h = F.gelu(self.input(x))
        for conv, norm in zip(self.convs, self.norms):
            h = norm(h + F.gelu(conv(h, edge_index)))
            h = F.dropout(h, p=self.cfg.dropout, training=self.training)
        return h

    def edge_scores(self, h: Tensor, edge_index: Tensor) -> Tensor:
        src, dst = edge_index
        pair = torch.cat([h[src], h[dst]], dim=-1)
        return torch.sigmoid(self.exploitability(pair)).squeeze(-1)

    def chain_score(self, h: Tensor, entry: Tensor, mid: Tensor, target: Tensor) -> Tensor:
        """Score a 3-point path sketch (entry -> pivot -> crown jewel)."""
        triple = torch.cat([h[entry], h[mid], h[target]], dim=-1)
        return torch.sigmoid(self.chain(triple)).squeeze(-1)

    def node_impact(self, h: Tensor) -> Tensor:
        return torch.sigmoid(self.impact(h)).squeeze(-1)

    def forward(self, x: Tensor, edge_index: Tensor) -> dict[str, Tensor]:
        h = self.encode(x, edge_index)
        return {
            "embeddings": h,
            "edge_exploitability": self.edge_scores(h, edge_index),
            "impact": self.node_impact(h),
        }

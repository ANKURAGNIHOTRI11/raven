"""Adversarial-robustness monitor for the GNN itself.

Two attack surfaces are watched:

* Data poisoning / evasion - a feed that has been manipulated to inject nodes
  or edges that shift rankings. Detected by comparing the live snapshot's
  structural statistics against a rolling baseline, and by a randomised-
  smoothing check: if small perturbations of the input features swing a node's
  score wildly, that node's score is not trustworthy and is flagged rather
  than published.
* Weight tampering - a model file swapped on disk or in the registry. Detected
  by hashing parameter tensors at load time and comparing against the recorded
  fingerprint.
"""
from __future__ import annotations

import hashlib
import statistics
from dataclasses import dataclass, field

import torch


def weight_fingerprint(model: torch.nn.Module) -> str:
    h = hashlib.sha256()
    for name, param in sorted(model.state_dict().items()):
        h.update(name.encode())
        h.update(param.detach().to("cpu").contiguous().numpy().tobytes())
    return h.hexdigest()


@dataclass
class StructuralBaseline:
    node_counts: dict[str, float] = field(default_factory=dict)
    mean_degree: float = 0.0
    samples: int = 0

    def update(self, kinds: list[str], degree: float) -> None:
        counts: dict[str, float] = {}
        for k in kinds:
            counts[k] = counts.get(k, 0.0) + 1.0
        n = self.samples
        for k, v in counts.items():
            prior = self.node_counts.get(k, v)
            self.node_counts[k] = (prior * n + v) / (n + 1)
        self.mean_degree = (self.mean_degree * n + degree) / (n + 1)
        self.samples = n + 1

    def drift(self, kinds: list[str], degree: float) -> tuple[float, list[str]]:
        if self.samples < 3:
            return 0.0, []
        reasons, deltas = [], []
        counts: dict[str, float] = {}
        for k in kinds:
            counts[k] = counts.get(k, 0.0) + 1.0
        for k, expected in self.node_counts.items():
            actual = counts.get(k, 0.0)
            if expected > 10:
                rel = abs(actual - expected) / expected
                deltas.append(rel)
                if rel > 0.5:
                    reasons.append(f"node_count:{k}:{actual:.0f}vs{expected:.0f}")
        if self.mean_degree > 0:
            rel = abs(degree - self.mean_degree) / self.mean_degree
            deltas.append(rel)
            if rel > 0.6:
                reasons.append(f"mean_degree:{degree:.2f}vs{self.mean_degree:.2f}")
        return (max(deltas) if deltas else 0.0), reasons


@torch.no_grad()
def smoothing_instability(model, x: torch.Tensor, edge_index: torch.Tensor,
                          trials: int = 8, sigma: float = 0.03) -> torch.Tensor:
    """Per-node score variance under small input noise. High variance means the
    ranking for that node sits on a decision boundary an attacker could push."""
    model.eval()
    runs = []
    for _ in range(trials):
        noisy = (x + torch.randn_like(x) * sigma).clamp(0.0, 1.0)
        runs.append(model(noisy, edge_index)["impact"])
    stacked = torch.stack(runs)
    return stacked.std(dim=0)


def instability_summary(std: torch.Tensor, threshold: float = 0.08) -> tuple[int, float]:
    values = std.detach().to("cpu").tolist()
    flagged = sum(1 for v in values if v > threshold)
    return flagged, (statistics.fmean(values) if values else 0.0)

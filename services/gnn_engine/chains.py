"""Attack-path ranking and exploit-chain prediction.

Per-CVE severity misses the case that actually breaks organisations: three
medium-severity issues that compose. The search below runs over the
GNN-weighted graph, so an edge's cost reflects learned exploitability rather
than CVSS alone, and a path made of low-severity links can still surface at the
top of the queue when it terminates on a crown-jewel asset.
"""
from __future__ import annotations

import hashlib
import heapq
import math
from collections import defaultdict
from dataclasses import dataclass

TRAVERSABLE = {
    "AFFECTED_BY", "CONNECTS_TO", "USES_TECHNIQUE", "WEAKNESS", "ENABLES", "MAPS_TO",
}


@dataclass
class ScoredPath:
    nodes: list[str]
    feasibility: float
    impact: float
    cves: list[str]
    hops: int

    @property
    def risk(self) -> float:
        return self.feasibility * self.impact

    @property
    def path_id(self) -> str:
        return hashlib.sha1("->".join(self.nodes).encode()).hexdigest()[:24]


def build_adjacency(snapshot, edge_weights) -> dict[int, list[tuple[int, float, str]]]:
    adj: dict[int, list[tuple[int, float, str]]] = defaultdict(list)
    src, dst = snapshot.edge_index.tolist()
    for i, (a, b) in enumerate(zip(src, dst)):
        kind = snapshot.edge_kinds[i] if i < len(snapshot.edge_kinds) else "REL"
        if kind.replace("_rev", "") not in TRAVERSABLE:
            continue
        w = float(edge_weights[i])
        adj[a].append((b, max(w, 1e-4), kind))
    return adj


def entry_points(snapshot) -> list[int]:
    """Where an unauthenticated attacker can start."""
    out = []
    for key, idx in snapshot.index.items():
        meta = snapshot.meta.get(key, {})
        if snapshot.kinds[idx] == "asset" and meta.get("exposed"):
            out.append(idx)
    if not out:  # no internet-facing asset recorded: treat DMZ-less estate as
        out = [i for i, k in enumerate(snapshot.kinds) if k == "asset"][:50]
    return out


def crown_jewels(snapshot, min_criticality: int = 4) -> list[int]:
    return [
        idx for key, idx in snapshot.index.items()
        if snapshot.kinds[idx] == "asset"
        and float(snapshot.meta.get(key, {}).get("criticality", 0)) >= min_criticality
    ]


def widest_paths(adj, sources: list[int], targets: set[int], max_hops: int = 6,
                 beam: int = 4000) -> dict[int, tuple[float, list[int]]]:
    """Maximum-feasibility path search.

    Feasibility multiplies along a path, so this is a shortest-path problem in
    -log space. Dijkstra with a beam cap keeps it bounded on estates with tens
    of thousands of nodes.
    """
    best: dict[int, tuple[float, list[int]]] = {}
    heap: list[tuple[float, int, list[int]]] = []
    for s in sources:
        heapq.heappush(heap, (0.0, s, [s]))
        best[s] = (1.0, [s])
    visited = 0
    found: dict[int, tuple[float, list[int]]] = {}
    while heap and visited < beam:
        cost, node, path = heapq.heappop(heap)
        visited += 1
        feas = math.exp(-cost)
        if node in targets and len(path) > 1:
            if node not in found or feas > found[node][0]:
                found[node] = (feas, path)
        if len(path) > max_hops:
            continue
        for nxt, w, _kind in adj.get(node, []):
            if nxt in path:
                continue
            new_cost = cost - math.log(min(max(w, 1e-4), 1.0))
            prior = best.get(nxt)
            if prior is None or math.exp(-new_cost) > prior[0]:
                best[nxt] = (math.exp(-new_cost), path + [nxt])
                heapq.heappush(heap, (new_cost, nxt, path + [nxt]))
    return found


def score_paths(snapshot, adj, impacts, max_paths: int = 200) -> list[ScoredPath]:
    sources = entry_points(snapshot)
    targets = set(crown_jewels(snapshot))
    if not targets:
        targets = set(i for i, k in enumerate(snapshot.kinds) if k == "asset")
    found = widest_paths(adj, sources, targets)

    paths: list[ScoredPath] = []
    for target, (feasibility, node_path) in found.items():
        keys = [snapshot.keys[i] for i in node_path]
        cves = [snapshot.keys[i] for i in node_path if snapshot.kinds[i] == "vulnerability"]
        impact = float(impacts[target])
        crit = float(snapshot.meta.get(snapshot.keys[target], {}).get("criticality", 3)) / 5.0
        paths.append(ScoredPath(
            nodes=keys,
            feasibility=round(feasibility, 4),
            impact=round(0.5 * impact + 0.5 * crit, 4),
            cves=cves,
            hops=len(node_path) - 1,
        ))
    paths.sort(key=lambda p: p.risk, reverse=True)
    return paths[:max_paths]


def sleeper_chains(snapshot, paths: list[ScoredPath], severity_cap: float = 7.0,
                   risk_floor: float = 0.25) -> list[ScoredPath]:
    """The headline output of this layer.

    A sleeper chain is a path where *every* link is below the severity a triage
    queue would escalate, yet the composed path reaches a critical asset with
    meaningful feasibility. These are the findings a CVSS-ordered backlog
    never gets to.
    """
    out = []
    for p in paths:
        if len(p.cves) < 2 or p.risk < risk_floor:
            continue
        scores = [float(snapshot.meta.get(c, {}).get("cvss", 0.0)) for c in p.cves]
        if scores and max(scores) < severity_cap:
            out.append(p)
    return out

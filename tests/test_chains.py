"""The sleeper-chain case, end to end over the search, with no model involved."""
import torch

from chains import ScoredPath, build_adjacency, score_paths, sleeper_chains
from graphio import GraphSnapshot


def snapshot():
    keys = ["login01", "CVE-A", "jump01", "CVE-B", "db01"]
    kinds = ["asset", "vulnerability", "asset", "vulnerability", "asset"]
    index = {k: i for i, k in enumerate(keys)}
    meta = {
        "login01": {"exposed": True, "criticality": 2, "cvss": 0.0},
        "CVE-A": {"cvss": 5.3, "exposed": False, "criticality": 0},
        "jump01": {"exposed": False, "criticality": 3, "cvss": 0.0},
        "CVE-B": {"cvss": 6.1, "exposed": False, "criticality": 0},
        "db01": {"exposed": False, "criticality": 5, "cvss": 0.0},
    }
    src = [0, 1, 2, 3]
    dst = [1, 2, 3, 4]
    edge_index = torch.tensor([src, dst], dtype=torch.long)
    x = torch.zeros((5, 16))
    return GraphSnapshot(x, edge_index, keys, index, kinds,
                         ["AFFECTED_BY", "CONNECTS_TO", "AFFECTED_BY", "CONNECTS_TO"], meta)


def test_two_medium_cves_compose_into_a_flagged_chain():
    snap = snapshot()
    weights = [0.8, 0.9, 0.8, 0.9]
    adj = build_adjacency(snap, weights)
    paths = score_paths(snap, adj, [0.2, 0.2, 0.4, 0.2, 0.95])
    assert paths, "path search found nothing"
    best = paths[0]
    assert best.nodes[-1] == "db01" and len(best.cves) == 2

    sleepers = sleeper_chains(snap, paths)
    assert sleepers, "a path of two sub-7.0 CVEs to a criticality-5 asset should be flagged"
    assert sleepers[0].cves == ["CVE-A", "CVE-B"]


def test_a_single_high_severity_link_is_not_a_sleeper_chain():
    snap = snapshot()
    snap.meta["CVE-A"]["cvss"] = 9.1
    adj = build_adjacency(snap, [0.8, 0.9, 0.8, 0.9])
    paths = score_paths(snap, adj, [0.2, 0.2, 0.4, 0.2, 0.95])
    assert not sleeper_chains(snap, paths)

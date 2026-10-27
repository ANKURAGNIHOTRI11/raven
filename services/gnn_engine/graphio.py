"""Pull the attack graph out of Neo4j and turn it into tensors."""
from __future__ import annotations

from dataclasses import dataclass, field

import torch
from torch import Tensor

from model import NODE_TYPES, NUM_NUMERIC, NUM_TYPES

FETCH_NODES = """
MATCH (n)
WHERE n:Asset OR n:Vulnerability OR n:CWE OR n:AttackPattern OR n:Technique OR n:Zone
RETURN
  coalesce(n.asset_id, n.cve_id, n.id, n.name) AS key,
  labels(n)[0] AS label,
  coalesce(n.cvss_base, 0.0) AS cvss,
  coalesce(n.epss, 0.0) AS epss,
  coalesce(n.epss_percentile, 0.0) AS epss_pct,
  coalesce(n.kev, false) AS kev,
  coalesce(n.criticality, 0) AS criticality,
  coalesce(n.internet_exposed, false) AS exposed,
  coalesce(n.source_trust, 0.5) AS trust,
  coalesce(n.exploit_maturity, 'none') AS maturity,
  coalesce(size(n.controls), 0) AS controls,
  coalesce(n.environment, '') AS environment
"""

FETCH_EDGES = """
MATCH (a)-[r]->(b)
WHERE (a:Asset OR a:Vulnerability OR a:CWE OR a:AttackPattern OR a:Technique OR a:Zone)
  AND (b:Asset OR b:Vulnerability OR b:CWE OR b:AttackPattern OR b:Technique OR b:Zone)
RETURN coalesce(a.asset_id, a.cve_id, a.id, a.name) AS src,
       coalesce(b.asset_id, b.cve_id, b.id, b.name) AS dst,
       type(r) AS kind
"""

LABEL_TO_TYPE = {
    "Asset": "asset", "Vulnerability": "vulnerability", "CWE": "cwe",
    "AttackPattern": "attack_pattern", "Technique": "technique", "Zone": "zone",
}
MATURITY = {"none": 0.0, "poc": 0.34, "functional": 0.67, "weaponized": 1.0}
ENV_WEIGHT = {"prod": 1.0, "staging": 0.6, "dev": 0.35, "lab": 0.2, "": 0.5}


@dataclass
class GraphSnapshot:
    x: Tensor
    edge_index: Tensor
    keys: list[str]
    index: dict[str, int]
    kinds: list[str]
    edge_kinds: list[str]
    meta: dict[str, dict] = field(default_factory=dict)

    @property
    def num_nodes(self) -> int:
        return self.x.size(0)


def featurize(row: dict) -> list[float]:
    kind = LABEL_TO_TYPE.get(row["label"], "asset")
    onehot = [1.0 if kind == t else 0.0 for t in NODE_TYPES]
    numeric = [
        float(row["cvss"]) / 10.0,
        float(row["epss"]),
        float(row["epss_pct"]),
        1.0 if row["kev"] else 0.0,
        float(row["criticality"]) / 5.0,
        1.0 if row["exposed"] else 0.0,
        float(row["trust"]),
        MATURITY.get(str(row["maturity"]), 0.0),
        min(float(row["controls"]), 5.0) / 5.0,
        ENV_WEIGHT.get(str(row["environment"]), 0.5),
    ]
    assert len(onehot) == NUM_TYPES and len(numeric) == NUM_NUMERIC
    return onehot + numeric


async def load_snapshot(driver, device: str = "cpu") -> GraphSnapshot:
    async with driver.session() as s:
        node_rows = await (await s.run(FETCH_NODES)).data()
        edge_rows = await (await s.run(FETCH_EDGES)).data()

    keys, feats, kinds, meta = [], [], [], {}
    index: dict[str, int] = {}
    for row in node_rows:
        key = row["key"]
        if key is None or key in index:
            continue
        index[key] = len(keys)
        keys.append(key)
        kinds.append(LABEL_TO_TYPE.get(row["label"], "asset"))
        feats.append(featurize(row))
        meta[key] = row

    src, dst, edge_kinds = [], [], []
    for row in edge_rows:
        a, b = index.get(row["src"]), index.get(row["dst"])
        if a is None or b is None:
            continue
        # The graph is directed by semantics but traversable both ways for
        # message passing; direction is preserved separately for path search.
        src += [a, b]
        dst += [b, a]
        edge_kinds += [row["kind"], f"{row['kind']}_rev"]

    x = torch.tensor(feats or [[0.0] * (NUM_TYPES + NUM_NUMERIC)], dtype=torch.float32, device=device)
    edge_index = torch.tensor([src or [0], dst or [0]], dtype=torch.long, device=device)
    return GraphSnapshot(x, edge_index, keys, index, kinds, edge_kinds, meta)

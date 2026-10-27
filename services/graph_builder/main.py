"""Security ontology loader: projects normalized records into the Neo4j attack
graph as STIX-2.1-shaped nodes, and keeps the Qdrant vector store in sync for
the RAG side of the LLM gateway.

Graph shape
-----------
(:Asset)-[:AFFECTED_BY {confidence}]->(:Vulnerability)
(:Vulnerability)-[:WEAKNESS]->(:CWE)-[:ENABLES]->(:AttackPattern)
(:AttackPattern)-[:MAPS_TO]->(:Technique)
(:Asset)-[:CONNECTS_TO {trust_boundary}]->(:Asset)
(:Asset)-[:IN_ZONE]->(:Zone)

The CONNECTS_TO edges are what make exploit-chain prediction possible: a
low-severity CVE on a DMZ jump host only matters because of where that host
can reach.
"""
from __future__ import annotations

import asyncio

import httpx
from neo4j import AsyncGraphDatabase

from raven_common import bus, topics
from raven_common.metrics import ERRORS, GRAPH_NODES
from raven_common.models import Asset, NormalizedVulnerability
from raven_common.runtime import bootstrap, run

SERVICE = "graph-builder"
settings, log = bootstrap(SERVICE)

CONSTRAINTS = [
    "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
    "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE",
    "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (c:AttackPattern) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT zone_id IF NOT EXISTS FOR (z:Zone) REQUIRE z.name IS UNIQUE",
]

UPSERT_VULN = """
MERGE (v:Vulnerability {cve_id: $cve_id})
SET v.title = $title, v.description = left($description, 4000),
    v.cvss_base = $cvss_base, v.severity = $severity,
    v.epss = $epss, v.epss_percentile = $epss_percentile,
    v.kev = $kev, v.exploit_maturity = $maturity,
    v.source_trust = $source_trust, v.updated_at = timestamp()
WITH v
UNWIND CASE WHEN size($cwe_ids) = 0 THEN [null] ELSE $cwe_ids END AS cwe
FOREACH (_ IN CASE WHEN cwe IS NULL THEN [] ELSE [1] END |
  MERGE (c:CWE {id: cwe})
  MERGE (v)-[:WEAKNESS]->(c))
"""

LINK_ASSETS = """
MATCH (v:Vulnerability {cve_id: $cve_id})
UNWIND $asset_ids AS aid
MATCH (a:Asset {asset_id: aid})
MERGE (a)-[r:AFFECTED_BY]->(v)
SET r.confidence = $confidence, r.updated_at = timestamp()
"""

UPSERT_ASSET = """
MERGE (a:Asset {asset_id: $asset_id})
SET a.hostname = $hostname, a.kind = $kind, a.environment = $environment,
    a.criticality = $criticality, a.internet_exposed = $internet_exposed,
    a.owner = $owner, a.controls = $controls, a.updated_at = timestamp()
MERGE (z:Zone {name: $zone})
MERGE (a)-[:IN_ZONE]->(z)
WITH a
UNWIND CASE WHEN size($connects_to) = 0 THEN [null] ELSE $connects_to END AS peer
FOREACH (_ IN CASE WHEN peer IS NULL THEN [] ELSE [1] END |
  MERGE (p:Asset {asset_id: peer})
  MERGE (a)-[:CONNECTS_TO]->(p))
"""

# CWE -> CAPEC -> ATT&CK, the part of the ontology that lets the GNN reason
# about what an attacker does with a weakness rather than just its score.
CWE_CAPEC_ATTACK = {
    "CWE-787": ("CAPEC-100", "T1203"), "CWE-79": ("CAPEC-63", "T1059.007"),
    "CWE-89": ("CAPEC-66", "T1190"), "CWE-416": ("CAPEC-100", "T1203"),
    "CWE-78": ("CAPEC-88", "T1059"), "CWE-20": ("CAPEC-153", "T1190"),
    "CWE-125": ("CAPEC-540", "T1203"), "CWE-22": ("CAPEC-126", "T1083"),
    "CWE-352": ("CAPEC-62", "T1185"), "CWE-434": ("CAPEC-650", "T1505.003"),
    "CWE-862": ("CAPEC-115", "T1078"), "CWE-863": ("CAPEC-122", "T1068"),
    "CWE-269": ("CAPEC-233", "T1068"), "CWE-502": ("CAPEC-586", "T1203"),
    "CWE-798": ("CAPEC-70", "T1078"), "CWE-306": ("CAPEC-115", "T1078"),
    "CWE-918": ("CAPEC-664", "T1190"), "CWE-77": ("CAPEC-248", "T1059"),
    "CWE-190": ("CAPEC-92", "T1203"), "CWE-732": ("CAPEC-1", "T1222"),
}

MAP_TECHNIQUES = """
UNWIND $rows AS row
MATCH (c:CWE {id: row.cwe})
MERGE (p:AttackPattern {id: row.capec})
MERGE (c)-[:ENABLES]->(p)
MERGE (t:Technique {id: row.technique})
MERGE (p)-[:MAPS_TO]->(t)
WITH row
MATCH (v:Vulnerability)-[:WEAKNESS]->(:CWE {id: row.cwe})
MATCH (t:Technique {id: row.technique})
MERGE (v)-[:USES_TECHNIQUE]->(t)
"""


async def ensure_collection(client: httpx.AsyncClient) -> None:
    try:
        await client.put(
            f"{settings.qdrant_url}/collections/raven_vulns",
            json={"vectors": {"size": 768, "distance": "Cosine"}},
            timeout=30,
        )
    except Exception as exc:
        log.debug("qdrant_collection", error=str(exc)[:160])


async def embed_and_store(client: httpx.AsyncClient, v: NormalizedVulnerability) -> None:
    """Evidence for RAG. The payload keeps the citation id so the gateway can
    require a source reference for every claim."""
    try:
        r = await client.post(
            "http://embedder:8080/embed",
            json={"texts": [f"{v.cve_id} {v.title}\n{v.description[:2000]}"]},
            timeout=60,
        )
        vector = r.json()["embeddings"][0]
    except Exception as exc:
        log.debug("embed_skip", cve=v.cve_id, error=str(exc)[:160])
        return
    point_id = abs(hash(v.cve_id)) % (2**63)
    try:
        await client.put(
            f"{settings.qdrant_url}/collections/raven_vulns/points",
            json={"points": [{
                "id": point_id,
                "vector": vector,
                "payload": {
                    "cve_id": v.cve_id, "title": v.title,
                    "text": v.description[:4000], "severity": v.severity,
                    "kev": v.kev, "cvss": v.cvss_base,
                    "citation": f"{v.cve_id}@{','.join(v.provenance[:3])}",
                },
            }]},
            timeout=30,
        )
    except Exception as exc:
        log.debug("qdrant_upsert_failed", error=str(exc)[:160])


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
    async with driver.session() as s:
        for stmt in CONSTRAINTS:
            await s.run(stmt)

    producer = await bus.Producer(SERVICE).start()
    from raven_common.db import conn as pgconn

    async with httpx.AsyncClient() as client:
        await ensure_collection(client)

        async def pump_assets() -> None:
            async for asset in bus.consume(
                [topics.ASSET_EVENTS], "graph-assets", Asset, SERVICE
            ):
                async with driver.session() as s:
                    await s.run(
                        UPSERT_ASSET,
                        asset_id=asset.asset_id, hostname=asset.hostname, kind=asset.kind,
                        environment=asset.environment, criticality=asset.criticality,
                        internet_exposed=asset.internet_exposed, owner=asset.owner,
                        controls=asset.compensating_controls, zone=asset.zone,
                        connects_to=asset.connects_to,
                    )
                log.info("asset_graphed", asset=asset.asset_id)

        async def pump_vulns() -> None:
            async for v in bus.consume(
                [topics.NORMALIZED_VULNS], "graph-vulns", NormalizedVulnerability, SERVICE
            ):
                try:
                    async with pgconn() as c:
                        rows = await c.fetch(
                            "SELECT asset_id FROM findings WHERE cve_id=$1 AND state='open'",
                            v.cve_id,
                        )
                    asset_ids = [r["asset_id"] for r in rows]
                    rows_map = [
                        {"cwe": cwe, "capec": CWE_CAPEC_ATTACK[cwe][0],
                         "technique": CWE_CAPEC_ATTACK[cwe][1]}
                        for cwe in v.cwe_ids if cwe in CWE_CAPEC_ATTACK
                    ]
                    async with driver.session() as s:
                        await s.run(
                            UPSERT_VULN,
                            cve_id=v.cve_id, title=v.title, description=v.description,
                            cvss_base=v.cvss_base, severity=v.severity,
                            epss=v.epss_score, epss_percentile=v.epss_percentile,
                            kev=v.kev, maturity=v.exploit_maturity,
                            source_trust=v.source_trust, cwe_ids=v.cwe_ids,
                        )
                        if rows_map:
                            await s.run(MAP_TECHNIQUES, rows=rows_map)
                        if asset_ids:
                            await s.run(
                                LINK_ASSETS, cve_id=v.cve_id, asset_ids=asset_ids,
                                confidence=v.ingest_confidence,
                            )
                        counts = await (await s.run(
                            "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS c"
                        )).data()
                    for row in counts:
                        if row["label"]:
                            GRAPH_NODES.labels(row["label"]).set(row["c"])
                    await embed_and_store(client, v)
                    if asset_ids:
                        await producer.send(topics.GRAPH_UPDATES, v, key=v.cve_id)
                    log.info("vuln_graphed", cve=v.cve_id, assets=len(asset_ids))
                except Exception as exc:
                    ERRORS.labels(SERVICE, "graph").inc()
                    log.warning("graph_failed", cve=v.cve_id, error=str(exc)[:300])

        await asyncio.gather(pump_assets(), pump_vulns())


if __name__ == "__main__":
    run(main, SERVICE)

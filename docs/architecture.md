# RAVEN architecture

## 1. Data flow

```
feeds → crawler → raw.documents ─┬→ MinIO (WORM, content-addressed)
                                 └→ normalizer → normalized.vulnerabilities
                                        │              └→ quarantine.records
                                        ├→ PostgreSQL (system of record)
                                        └→ OpenSearch (full text)
                                            ↓
                                     graph-builder → Neo4j + Qdrant
                                            ↓
                                     gnn-engine → graph.signals
                                            ↓
                                     risk-engine → risk.assessments
                                            ↓
                                     agents ⇄ llm-gateway ⇄ vllm / embedder
                                            ↓
                              ABSTAIN / ANALYZE(sandbox) / ACT(remediation)
                                            ↓
                                  approvals → audit_log → feedback
                                            ↓
                              model trust, labeled dataset, GNN retrain
```

Every hop crosses Redpanda. Nothing calls another service's database directly; the
only synchronous HTTP calls are agents → llm-gateway, llm-gateway → vllm/embedder,
agents → sandbox, and the operator console → api.

## 2. Topics

| Topic | Producer | Consumer | Payload |
|---|---|---|---|
| `raven.raw.documents` | crawler | normalizer | `RawDocument` |
| `raven.normalized.vulnerabilities` | normalizer | graph-builder | `NormalizedVulnerability` |
| `raven.assets` | crawler (CMDB) | graph-builder | `Asset` |
| `raven.quarantine` | normalizer | api, feedback | `QuarantineRecord` |
| `raven.graph.signals` | gnn-engine | risk-engine | `GraphSignal` |
| `raven.attack.paths` | gnn-engine | api | `AttackPath` |
| `raven.risk.assessments` | risk-engine | agents | `RiskAssessment` |
| `raven.agent.decisions` | agents | remediation, feedback | `AgentDecision` |
| `raven.remediation.plans` | remediation | api | `RemediationPlan` |
| `raven.approvals` | api | remediation | approval events |
| `raven.feedback` | api, feedback | feedback | `FeedbackEvent` |

Schemas live in `libs/raven_common/models.py` as Pydantic models and are validated
**at the edge** — `bus.py` refuses to publish an invalid message and routes invalid
consumed messages to the quarantine handler rather than crashing the consumer.

## 3. Storage roles

- **MinIO** is append-only. Object keys are `sha256(body)`, so a re-fetched advisory
  collapses onto the same object and tampering is detectable by recompute. Retention
  lock is set at bucket creation; the platform holds no delete credential.
- **PostgreSQL** is the system of record: `sources`, `raw_documents`, `quarantine`,
  `vulnerabilities`, `assets`, `findings`, `graph_signals`, `risk_assessments`,
  `agent_decisions`, `approvals`, `feedback_events`, `model_trust`,
  `training_examples`, `audit_log`. Schema in `infra/postgres/init/001_schema.sql`.
- **Neo4j** holds the attack graph only: `(:Asset)`, `(:Vulnerability)`,
  `(:Technique)`, with `AFFECTS`, `REACHES`, `ENABLES` edges. It is derivable from
  PostgreSQL and can be rebuilt from scratch.
- **Qdrant** holds advisory and remediation embeddings for RAG. Also derivable.
- **OpenSearch** is a search index, never a source of truth.

## 4. Source registry and trust

Each feed carries a trust score in `sources.trust_score` (0–1). Seeded values put
NVD, CISA KEV, EPSS and the internal CMDB high; news sources low. Trust is used in
three places: conflict arbitration during merge (higher-trust field wins), the
`source_trust` risk feature, and the crawler's circuit-breaker tolerance. The feedback
engine adjusts trust when a source's claims are repeatedly overridden by analysts.

## 5. GNN engine

`AttackGraphNet` is a homogeneous graph network — node-type one-hot plus 10 numeric
features, two GATv2 layers then a SAGE layer, with three heads: exploitability, chain
probability, impact. Homogeneous rather than heterogeneous convolutions on purpose:
the estate is small enough that the hetero machinery costs more than it buys, and a
single tensor layout makes nightly retraining and drift comparison straightforward.

Path ranking is a widest-path Dijkstra over `-log(feasibility)` edge weights.
`sleeper_chains()` looks specifically for paths whose maximum single-CVE severity is
below the alerting threshold but whose composed feasibility to a critical asset is high.
These are the findings the platform exists to surface.

Training (`train.py`) is two-stage: self-supervised link prediction over the current
graph, then supervised fine-tune on `training_examples` rows produced by the feedback
engine from analyst decisions.

## 6. Risk engine

Twelve features, linear-with-controls fusion, bias `-4.2`. Notable weights:
chain score `1.90`, CVSS `1.35`, KEV `1.25`, EPSS percentile `1.10`, internet exposure
`0.95`, asset criticality `0.90`. Compensating controls apply a diminishing-returns
factor rather than a flat subtraction, so stacking five partial mitigations cannot
zero out a live KEV finding.

Confidence is derived from feature completeness and source agreement; the interval
is reported alongside every score and the agents layer gates on its lower bound, not
the point estimate.

## 7. Decision engine

```
risk assessment → policy gates → confidence gate → outcome
```

Twelve gates in `services/agents/policy.py`, including production-scope, destructive
command regexes, blast-radius ceiling, maintenance-window, rollback-plan-present, and
change-freeze. Any gate failure downgrades the outcome — gates can only make the
decision more conservative, never less. Below the confidence floor the outcome is
ABSTAIN with the reason recorded, which is a first-class result, not an error.

## 8. Observability

Every service exports Prometheus metrics on `:9100/metrics` via `raven_common.metrics`:
ingestion counters per source, quarantine rate, normalization latency, GNN recompute
duration, risk score histogram, LLM gateway guard events, decision outcome counters,
approval queue depth. The provisioned Grafana dashboard (`raven.json`) fronts these.

Logs are structured JSON (structlog) with a `correlation_id` propagated from the raw
document through to the agent decision, so any finding can be traced end to end.

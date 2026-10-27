# RAVEN

**R**isk-**A**ware **V**ulnerability **E**valuation **N**etwork — a fully containerized
vulnerability-intelligence platform that ingests public and internal feeds, builds an
attack graph over your estate, ranks exploit chains with a GNN, fuses a contextual risk
score with a confidence interval and evidence trail, and drives a guarded multi-agent
decision loop that never touches production without human approval.

Target host: bare-metal Ubuntu 22.04 LTS, single NVIDIA H200 (141 GB), CUDA driver ≥ 550,
Docker + NVIDIA Container Toolkit. Everything runs in containers; nothing is installed
into the host Python. On an aarch64/Grace-Hopper host, `vllm/vllm-openai` has no
published arm64 image — run `make vllm-gh200` once to build it natively from
source before `make up` (see `deploy/build_vllm_gh200.sh`).

---

## Quick start

```bash
sudo ./deploy/bootstrap_host.sh     # docker, nvidia-container-toolkit, vm.max_map_count
make env                            # copies .env.example -> .env
$EDITOR .env                        # set passwords + RAVEN_API_TOKEN, NVD_API_KEY
make base                           # builds raven-base-cpu:1.0 and raven-base-gpu:1.0
[ "$(uname -m)" = "aarch64" ] && make vllm-gh200  # Grace/GH200 hosts only, ~20-30 min
make build                          # builds the 12 service images
make up                             # starts the 22-container stack
make gpu-check                      # confirms the GPU is visible inside containers
make seed                           # loads seed/assets.json into the CMDB tables
make smoke                          # end-to-end health + pipeline check
```

Console: `http://<host>:8088/` — bearer token is `RAVEN_API_TOKEN` from `.env`.
Grafana: `http://<host>:3000/`. Prometheus: `http://<host>:9090/`.

First model pull takes a while: vLLM downloads `Qwen/Qwen2.5-32B-Instruct-AWQ`
(~19 GB) on first boot. `docker compose logs -f vllm` to watch it.

Useful targets: `make logs`, `make ps`, `make down`, `make reset` (destroys volumes),
`make train` (GNN retrain), `make backup`.

---

## What runs where

| Container | Role | GPU |
|---|---|---|
| redpanda | Kafka-compatible ingestion bus, 11 topics | — |
| postgres | System of record (14 tables) | — |
| neo4j | Attack graph: assets ↔ CVEs ↔ techniques | — |
| opensearch | Full-text advisory search | — |
| qdrant | RAG embeddings | — |
| minio | WORM raw-document archive (content-addressed) | — |
| redis | Locks, circuit-breaker state, approval queue | — |
| vllm | Qwen2.5-32B-Instruct-AWQ, OpenAI-compatible | yes |
| embedder | bge-base-en-v1.5 sentence embeddings | yes |
| crawler | NVD, KEV, EPSS, OSV, GHSA, PSIRT, RSS, CMDB | — |
| normalizer | Contract validation, BERT enrichment, dedup | yes |
| graph-builder | Ontology → Neo4j + Qdrant | — |
| gnn-engine | Attack-path ranking, chain prediction, robustness | yes |
| risk-engine | Fused score + CI + evidence trail | — |
| llm-gateway | Prompt Guard, RAG, model router, verifier | — |
| agents | ABSTAIN / ANALYZE / ACT decision engine | — |
| sandbox | Patch validation (isolated, read-only, no egress) | — |
| remediation | Ansible apply/validate/rollback bundle generation | — |
| feedback | Model trust scores, labeled dataset, retrain trigger | — |
| api | Operator API + console | — |
| prometheus / grafana / nginx | Telemetry and front door | — |

### H200 memory budget

| Consumer | Reservation | Notes |
|---|---|---|
| vLLM (Qwen2.5-32B-AWQ + KV cache) | ~101 GB | `--gpu-memory-utilization=0.72` |
| Embedder (bge-base) | ~2 GB | batch 64 |
| Normalizer BERT pass | ~3 GB | zero-shot exploit maturity + product NER |
| GNN engine | ~6 GB | GATv2 + SAGE, full-graph forward |
| Headroom | ~29 GB | retrain bursts, fragmentation |

To run the higher-quality model instead, set in `.env`:

```
RAVEN_LLM_MODEL=neuralmagic/Qwen2.5-72B-Instruct-FP8
RAVEN_VLLM_GPU_FRACTION=0.80
RAVEN_VLLM_MAX_MODEL_LEN=16384
```

and lower the normalizer batch size. 72B-FP8 leaves roughly 12 GB of headroom on a
single H200, so do not retrain the GNN while it is serving.

---

## The four novel layers

1. **GNN engine** — ranks attack paths by edge-weighted feasibility × impact, and
   predicts *exploit chains*: combinations of individually low-severity CVEs that
   together open a path to a critical asset (`sleeper_chains()`). An adversarial
   robustness monitor watches for graph poisoning, structural drift and weight tampering.
2. **Risk engine** — 12 weighted features (CVSS, EPSS v4 percentile, KEV flag, asset
   criticality, internet exposure, compensating controls, GNN blast radius and chain
   score, …) fused into a score with a confidence interval and a machine-readable
   evidence trail. Chain score is weighted above raw CVSS on purpose.
3. **LLM gateway** — instruction/data segmentation with nonce-sealed untrusted blocks,
   injection and secret-shape screening on both ingress and egress, RAG that requires
   citations resolvable to stored evidence IDs, and a verifier pass over every analysis.
4. **Multi-agent decision engine** — schema-checked parsing, confidence gating, 12 policy
   gates (destructive-command and scope regexes among them), and three outcomes:
   ABSTAIN → human queue, ANALYZE → sandbox validation, ACT → remediation bundle.
   Production changes always require a human approval with a rollback plan attached.

## Deliberate scope limits

- **No exploit or PoC execution.** The sandbox validates *patches* — dry-run package
  resolution, IaC lint, rollback symmetry — and nothing else. Running attacker code,
  even in a container, is not a risk this platform takes on. See `docs/threat-model.md`.
- **No unattended production change.** The remediation agent writes Ansible bundles.
  It only executes them if you wire `RAVEN_APPLY_HOOK` to your own runner, and the
  approval gate never auto-approves anything tagged production.
- **Feeds are untrusted by default.** Every record is contract-validated and
  adversarially screened before it reaches the ontology; failures are quarantined,
  not dropped.

## Layout

```
libs/raven_common/     shared contracts, bus, guard, storage, metrics, llm client
services/<name>/       one container each, main.py entrypoint
infra/                 postgres schema, nginx, prometheus, grafana provisioning
docker/                two shared base images + per-service Dockerfiles
deploy/                host bootstrap, smoke test
seed/                  12-node HPC asset estate for first boot
tests/                 24 unit tests (guard, scoring, policy, parsers, chains)
docs/                  architecture, threat model, runbook
```

Run the tests inside the CPU base image:

```bash
docker run --rm -v "$PWD:/app" -w /app raven-base-cpu:1.0 pytest -q
```

## Documentation

- `docs/architecture.md` — data flow, contracts, topics, schema
- `docs/threat-model.md` — §5.2 poisoned-feed defense, §5.4 LLM gateway hardening
- `docs/runbook.md` — day-2 operations, failure modes, recovery

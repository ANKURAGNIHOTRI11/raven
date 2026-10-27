# RAVEN

**R**isk-**A**ware **V**ulnerability **E**valuation **N**etwork — a fully containerized
vulnerability-intelligence platform that ingests public and internal feeds, builds an
attack graph over your estate, ranks exploit chains with a GNN, fuses a contextual risk
score with a confidence interval and evidence trail, and drives a guarded multi-agent
decision loop that never touches production without human approval.

Target host: bare-metal Ubuntu 22.04 LTS with an NVIDIA A100 80 GB, H100 80 GB, H200, or compatible GPU. The current deployment uses Docker Compose and the NVIDIA Container Toolkit. The default vLLM CUDA 12.9 image should use NVIDIA Linux driver 575.51.03 or newer; the bootstrap script checks this baseline. A native no-Docker deployment is not provided by this compose-based path.
---

## Quick start

```bash
sudo ./deploy/bootstrap_host.sh     # Docker, NVIDIA Container Toolkit, vm.max_map_count
make env                            # generates unique local secrets in .env (mode 600)
$EDITOR .env                        # configure optional feed/model settings; keep generated secrets
make validate-env                   # checks secret quality and Postgres DSN consistency
make up                             # builds images and starts the stack
make gpu-check                      # confirms GPU visibility inside containers
make seed                           # re-applies seed/assets.json via crawler startup
make smoke                          # end-to-end health/authentication checks
```

Console: `http://127.0.0.1:8088/` — bearer token is `RAVEN_API_TOKEN` from `.env`.
Grafana: `http://127.0.0.1:8088/grafana/`. Management ports bind to loopback by default; use an SSH tunnel for remote access.
Prometheus is reachable only on the Docker network by default. Do not publish the plain-HTTP console or management ports directly to the public internet.

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

### GPU placement and model sizing

The default compose configuration gives vLLM, the embedder, normalizer, and GNN independent GPU-device settings:
RAVEN_VLLM_GPU_DEVICE, RAVEN_EMBEDDER_GPU_DEVICE, RAVEN_NORMALIZER_GPU_DEVICE, and RAVEN_GNN_GPU_DEVICE (each defaults to 0). Set these to different device indices to split workloads across multiple GPUs. When all are 0, the models share the same selected GPU. The vLLM default caps its
own allocator target at 55% of the card's VRAM (RAVEN_VLLM_GPU_FRAC=0.55) and uses an
8,192-token context (RAVEN_VLLM_MAX_LEN=8192). These are starting settings, not a
benchmark or guarantee that every workload fits. Monitor nvidia-smi and the vLLM logs
on the actual node; tune concurrency, context length, and placement based on measured use.

The default model is Qwen/Qwen2.5-32B-Instruct-AWQ. An 80 GB A100 or H100 is the
intended starting class for this quantized model, but the normalizer, embedder, and GNN
also need GPU memory when all are active. If startup reports an out-of-memory error,
lower the context length or move companion workloads to another GPU before increasing
the vLLM memory fraction.

A 72B model is **not** the default for a single 80 GB A100/H100. This compose file
currently assigns vLLM to one selected GPU and co-locates other GPU workloads there.
Only try a 72B model after planning GPU placement and validating memory use on the
target hardware. For any model-size change, update both model settings so the analyst
and verifier names match the model served by vLLM:

    RAVEN_VLLM_MODEL=Qwen/Qwen2.5-72B-Instruct-AWQ
    RAVEN_VERIFIER_MODEL=Qwen/Qwen2.5-72B-Instruct-AWQ
    RAVEN_VLLM_GPU_FRAC=0.70
    RAVEN_VLLM_MAX_LEN=8192

That example is a hardware-dependent tuning example, not a validated production
profile. On a single 80 GB card, do not co-locate the embedder, normalizer, and GNN on
that same GPU without independent sizing and testing. If you have multiple GPUs, use
the per-service GPU-device settings above to move companion workloads.
The current project CI validates source tests and Compose syntax; it does not load a
large model or certify GPU memory fit.

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
tests/                 unit and regression tests (guard, scoring, policy, parsers, chains)
docs/                  architecture, threat model, runbook
```

Run unit tests in an isolated Python environment (CPU PyTorch is sufficient for these tests):

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e ./libs/raven_common pytest torch-geometric==2.6.1
TRANSFORMERS_OFFLINE=1 python -m pytest -q
```

## Documentation

- `docs/architecture.md` — data flow, contracts, topics, schema
- `docs/threat-model.md` — §5.2 poisoned-feed defense, §5.4 LLM gateway hardening
- `docs/runbook.md` — day-2 operations, failure modes, recovery

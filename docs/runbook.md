# RAVEN runbook

## Daily

1. Console → **Queue**: work the approval queue. Anything older than its SLA band is
   highlighted. Every item carries a rollback plan; if it does not, the gate failed and
   the item should be rejected, not fixed by hand.
2. Console → **Quarantine**: check the rate. A steady trickle is normal (malformed RSS).
   A spike from one source means either a feed format change or an attack — check
   `quarantine.reason` groupings before reopening the circuit breaker.
3. Grafana → *RAVEN overview*: ingestion lag, GNN recompute duration, guard events.
   Non-zero guard events are worth reading; they are logged with the source document ID.

## Common operations

```bash
make ps                                  # container health
make logs                                # all services, follow
docker compose logs -f normalizer        # one service
make gpu-check                           # nvidia-smi inside the GPU containers
make train                               # GNN retrain (link-pred + supervised)
make backup                              # pg_dump + neo4j dump + qdrant snapshot
make reset                               # DESTROYS all volumes
```

Reopen a tripped circuit breaker:

```bash
docker compose exec redis redis-cli DEL raven:breaker:<source_id>
```

Re-run a quarantined record after fixing a parser:

```bash
docker compose exec api python -m raven_common.tools.requeue --quarantine-id <id>
```

Rebuild the graph from PostgreSQL (safe — Neo4j is derived):

```bash
docker compose stop gnn-engine
docker compose exec graph-builder python -m services.graph_builder.main --rebuild
docker compose start gnn-engine
```

## Failure modes

**vLLM will not start / OOM.** Almost always the GPU fraction. Check nothing else grabbed
memory (`nvidia-smi`), then lower `RAVEN_VLLM_GPU_FRACTION` or
`RAVEN_VLLM_MAX_MODEL_LEN`. If you swapped to the 72B-FP8 model, stop the GNN retrain
job — the two do not co-exist on one H200.

**OpenSearch exits immediately.** `vm.max_map_count` too low. `bootstrap_host.sh` sets it;
re-run `sudo sysctl -w vm.max_map_count=262144` and persist it in `/etc/sysctl.conf`.

**Crawler gets 403 from NVD.** Missing or rate-limited `NVD_API_KEY`. Without a key you
are capped at 5 requests / 30s and the backoff will look like a stall.

**Normalizer lag climbing.** BERT enrichment is the bottleneck. Either reduce
`RAVEN_NORMALIZER_BATCH` (less GPU contention) or scale the normalizer to two replicas
if headroom allows — it is stateless and consumer-group balanced.

**Everything ABSTAINs.** Usually confidence floor vs. sparse evidence. Check that the
CMDB seeded (`make seed`) and that Qdrant has embeddings — with no asset criticality or
retrievable evidence, low confidence is the correct behaviour, not a bug.

**GNN halts with a weight fingerprint mismatch.** Do not override it. Either a retrain
completed and was not registered, or the weights changed under you. Verify the model
file hash against `model_trust` before re-registering.

## Recovery

Neo4j, Qdrant and OpenSearch are all derived stores — drop and rebuild from PostgreSQL.
PostgreSQL and MinIO are the only things that must be backed up. `make backup` writes
to `./backups/<timestamp>/`; ship that off-host.

Full restore:

```bash
make down
docker volume rm raven_pgdata
make up
docker compose exec -T postgres psql -U raven raven < backups/<ts>/postgres.sql
docker compose exec graph-builder python -m services.graph_builder.main --rebuild
```

## Before going live

- Rotate `RAVEN_API_TOKEN`, `POSTGRES_PASSWORD`, `NEO4J_AUTH`, `MINIO_ROOT_PASSWORD`.
- Replace the nginx TLS stub with real certificates and put SSO in front of it.
- Point `seed/assets.json` at your real CMDB export, or wire the CMDB crawler parser to
  your inventory API. The chain predictions are worth exactly as much as this data.
- Decide your `RAVEN_APPLY_HOOK` policy. Leaving it unset is a legitimate permanent
  choice — the platform is fully useful as a ranking and bundle-generation system.
- Ship `audit_log` to a WORM destination.

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
make migrate                             # apply idempotent Postgres migrations
make backup                              # timestamped PostgreSQL + MinIO cold backup
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

**vLLM will not start / OOM.** Check current use with `nvidia-smi`, then lower
`RAVEN_VLLM_GPU_FRAC` or `RAVEN_VLLM_MAX_LEN`. You can also assign companion workers
to another GPU using `RAVEN_EMBEDDER_GPU_DEVICE`, `RAVEN_NORMALIZER_GPU_DEVICE`, and
`RAVEN_GNN_GPU_DEVICE`. Do not assume a 72B model plus the other workers fits on an
80 GB card; validate the exact model/context/traffic profile before production use.

**OpenSearch exits immediately.** `vm.max_map_count` too low. `bootstrap_host.sh` sets it;
re-run `sudo sysctl -w vm.max_map_count=262144` and persist it in `/etc/sysctl.conf`.

**Crawler gets 403 from NVD.** Missing or rate-limited `NVD_API_KEY`. Without a key you
are capped at 5 requests / 30s and the backoff will look like a stall.

**Normalizer lag climbing.** BERT enrichment may be the bottleneck. Check GPU use and
service logs; if multiple GPUs are available, move it with `RAVEN_NORMALIZER_GPU_DEVICE`.
The normalizer's batch size is currently configured in code, not through a documented
`RAVEN_NORMALIZER_BATCH` environment variable.

**Everything ABSTAINs.** Usually confidence floor vs. sparse evidence. Check that the
CMDB seeded (`make seed`) and that Qdrant has embeddings — with no asset criticality or
retrievable evidence, low confidence is the correct behaviour, not a bug.

**GNN halts with a weight fingerprint mismatch.** Do not override it. Either a retrain
completed and was not registered, or the weights changed under you. Verify the model
file hash against `model_trust` before re-registering.

## Recovery

Neo4j, Qdrant and OpenSearch are derived stores. PostgreSQL contains structured state;
MinIO contains the raw-document archive, so both are backed up. `make backup` creates
`backups/<YYYY-MM-DD-HHMMSS>/postgres.sql.gz` and
`backups/<YYYY-MM-DD-HHMMSS>/minio-data.tar.gz`. MinIO is briefly stopped for a
consistent cold archive and restarted afterward. Copy the backup directory securely
off-host.

Full restore is a maintenance operation. Keep all application services stopped while
restoring. Restore the MinIO archive into the Compose volume labelled `miniodata`, then
start only PostgreSQL, restore the SQL dump, apply migrations, and start the remaining
services:

```bash
make down
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-$(basename "$PWD")}
MINIO_VOLUME=$(docker volume ls --filter label=com.docker.compose.project="$PROJECT_NAME" --filter label=com.docker.compose.volume=miniodata -q | head -n1)
test -n "$MINIO_VOLUME"
docker run --rm -v "$MINIO_VOLUME:/data" -v "$PWD/backups/<timestamp>:/backup:ro" alpine:3.22 sh -ec 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar xzf /backup/minio-data.tar.gz -C /data'
docker compose up -d postgres
set -a; . ./.env; set +a
gzip -dc "backups/<timestamp>/postgres.sql.gz" | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"
make migrate
docker compose up -d
```

Keep a separate copy of `.env`; generated database credentials must match the restored
PostgreSQL data. Test the restore on a separate host before relying on it.

## Before going live

- Rotate `RAVEN_API_TOKEN`, `POSTGRES_PASSWORD`, `NEO4J_AUTH`, `MINIO_ROOT_PASSWORD`.
- The front door is local HTTP only. Configure real TLS and authentication before publishing any endpoint externally.
- Point `seed/assets.json` at your real CMDB export, or wire the CMDB crawler parser to
  your inventory API. The chain predictions are worth exactly as much as this data.
- Decide your `RAVEN_APPLY_HOOK` policy. Leaving it unset is a legitimate permanent
  choice — the platform is fully useful as a ranking and bundle-generation system.
- Ship `audit_log` to a WORM destination.

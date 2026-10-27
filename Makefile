SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help env validate-env base build up down logs ps gpu-check vllm-gh200 train seed smoke reset migrate backup

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

env: ## generate a fresh local .env with unique secrets; preserve existing .env
	@python3 deploy/init_env.py

validate-env: env ## validate unique secrets and database connection settings
	@python3 deploy/validate_env.py .env

base: ## build the CPU and GPU base images
	docker build -f docker/base.cpu.Dockerfile -t raven-base-cpu:1.0 .
	docker build -f docker/base.gpu.Dockerfile -t raven-base-gpu:1.0 .

vllm-gh200: ## optional: build a custom vLLM image on aarch64/Grace Hopper
	./deploy/build_vllm_gh200.sh
	@echo "Set RAVEN_VLLM_IMAGE=raven/vllm-gh200:local in .env to use the custom image."

build: validate-env base ## validate config and build every service image
	$(COMPOSE) build

up: build ## build, migrate the database, and start the platform
	$(COMPOSE) up -d postgres
	$(MAKE) migrate
	$(COMPOSE) up -d
	@set -a; . ./.env; set +a; port=8088; if [[ -n "$RAVEN_HTTP_PORT" ]]; then port="$RAVEN_HTTP_PORT"; fi; printf "console:    http://127.0.0.1:%s/\n" "$port"; printf "Grafana:    http://127.0.0.1:%s/grafana/ (via SSH tunnel recommended)\n" "$port"
	@echo "Neo4j HTTP/Bolt and MinIO Console are bound to loopback by default."
down: ## stop everything, keep the data
	$(COMPOSE) down

reset: ## stop everything and delete all volumes
	@echo "WARNING: this destroys all RAVEN container volumes."
	$(COMPOSE) down -v

logs: ## follow all service logs
	$(COMPOSE) logs -f --tail=100

ps: ## show container status
	$(COMPOSE) ps

gpu-check: ## confirm NVIDIA GPU visibility inside a container
	docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
	$(COMPOSE) exec gnn-engine python -c "import torch;print('torch',torch.__version__,'cuda',torch.cuda.is_available(),torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"

train: ## retrain the attack-graph network on the live graph
	$(COMPOSE) exec gnn-engine python train.py

seed: validate-env ## re-apply seed/assets.json through the crawler's startup seed routine
	$(COMPOSE) restart crawler

smoke: validate-env ## run end-to-end health and authentication checks
	@set -a; . ./.env; set +a; RAVEN_BASE="http://127.0.0.1:$${RAVEN_HTTP_PORT:-8088}" ./deploy/smoke_test.sh

migrate: validate-env ## apply idempotent Postgres migrations before services start
	@set -Eeuo pipefail; \
	set -a; . ./.env; set +a; \
	ready=0; \
	for attempt in $$(seq 1 60); do \
	  if $(COMPOSE) exec -T postgres pg_isready -h 127.0.0.1 -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" >/dev/null 2>&1; then ready=1; break; fi; \
	  sleep 2; \
	done; \
	if [[ "$$ready" != 1 ]]; then echo "Postgres did not become ready for migrations." >&2; exit 1; fi; \
	for migration in infra/postgres/migrations/*.sql; do \
	  echo "Applying $$migration"; \
	  $(COMPOSE) exec -T postgres psql -v ON_ERROR_STOP=1 -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" < "$$migration"; \
	done

backup: validate-env ## create timestamped PostgreSQL and MinIO cold backups
	@set -Eeuo pipefail; umask 077; \
	set -a; . ./.env; set +a; \
	stamp=$$(date +%F-%H%M%S); \
	backup_dir="$(CURDIR)/backups/$$stamp"; mkdir -p "$$backup_dir"; \
	$(COMPOSE) exec -T postgres pg_dump --clean --if-exists --no-owner --no-privileges -U "$$POSTGRES_USER" "$$POSTGRES_DB" | gzip -1 > "$$backup_dir/postgres.sql.gz"; \
	minio_id=$$($(COMPOSE) ps -aq minio | head -n1); \
	if [[ -z "$$minio_id" ]]; then echo "MinIO container not found; run make up first." >&2; exit 1; fi; \
	minio_was_running=$$($(COMPOSE) ps --status running -q minio); \
	restart_minio() { if [[ -n "$$minio_was_running" ]]; then $(COMPOSE) start minio >/dev/null; fi; }; \
	trap restart_minio EXIT; \
	if [[ -n "$$minio_was_running" ]]; then $(COMPOSE) stop minio >/dev/null; fi; \
	docker run --rm --volumes-from "$$minio_id:ro" -v "$$backup_dir:/backup" alpine:3.22 sh -ec 'tar czf /backup/minio-data.tar.gz -C /data .'; \
	restart_minio; trap - EXIT; \
	echo "Backup written to $$backup_dir (Postgres dump + MinIO object volume). Store it securely off-host."

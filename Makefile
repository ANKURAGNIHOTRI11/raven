SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help env validate-env base build up down logs ps gpu-check vllm-gh200 train seed smoke reset backup

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

up: build ## build and start the platform
	$(COMPOSE) up -d
	@set -a; . ./.env; set +a; echo "console:    http://127.0.0.1:$\{RAVEN_HTTP_PORT:-8088}/"; echo "Grafana:    http://127.0.0.1:$\{RAVEN_HTTP_PORT:-8088}/grafana/ (via SSH tunnel recommended)"
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
	@set -a; . ./.env; set +a; ./deploy/smoke_test.sh

backup: validate-env ## dump Postgres and the Neo4j graph
	@set -a; . ./.env; set +a; \
	mkdir -p backups; \
	$(COMPOSE) exec -T postgres pg_dump -U "$$POSTGRES_USER" "$$POSTGRES_DB" | gzip > "backups/postgres-$$(date +%F).sql.gz"; \
	$(COMPOSE) exec -T neo4j neo4j-admin database dump neo4j --to-stdout > "backups/neo4j-$$(date +%F).dump"; \
	echo "Wrote backups/ (store them securely off-host)."

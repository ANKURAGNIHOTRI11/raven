SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help env base build up down logs ps gpu-check vllm-gh200 train seed smoke reset backup

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

env: ## create .env from the template if it is missing
	@test -f .env || (cp .env.example .env && echo "wrote .env - edit the change-me values before make up")

base: ## build the two shared base images
	docker build -f docker/base.cpu.Dockerfile -t raven-base-cpu:1.0 .
	docker build -f docker/base.gpu.Dockerfile -t raven-base-gpu:1.0 .

vllm-gh200: ## aarch64/Grace hosts only - build vllm-openai from source (no arm64 image upstream)
	./deploy/build_vllm_gh200.sh

build: base ## build every service image
	$(COMPOSE) build

up: env build ## start the whole platform
	@if [ "$$(uname -m)" = "aarch64" ] && ! docker image inspect raven/vllm-gh200:local >/dev/null 2>&1; then \
		echo "aarch64 host and raven/vllm-gh200:local is missing - run 'make vllm-gh200' first (20-30 min build)."; \
		exit 1; \
	fi
	$(COMPOSE) up -d
	@echo "console:    http://localhost:8088"
	@echo "grafana:    http://localhost:8088/grafana"
	@echo "neo4j:      http://localhost:7474"
	@echo "minio:      http://localhost:9001"

down: ## stop everything, keep the data
	$(COMPOSE) down

reset: ## stop everything and delete all volumes
	$(COMPOSE) down -v

logs: ## follow all logs
	$(COMPOSE) logs -f --tail=100

ps: ## container status
	$(COMPOSE) ps

gpu-check: ## confirm the H200 is visible inside a container
	docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
	$(COMPOSE) exec gnn-engine python -c "import torch;print('torch',torch.__version__,'cuda',torch.cuda.is_available(),torch.cuda.get_device_name(0))"

train: ## retrain the attack-graph network on the live graph
	$(COMPOSE) exec gnn-engine python train.py

seed: ## push the CMDB/SBOM inventory again
	$(COMPOSE) restart crawler

smoke: ## end-to-end check with the synthetic estate
	$(COMPOSE) exec -T api python -c "print('api up')"
	./deploy/smoke_test.sh

backup: ## dump Postgres and the Neo4j graph
	@mkdir -p backups
	$(COMPOSE) exec -T postgres pg_dump -U $${POSTGRES_USER:-raven} raven | gzip > backups/raven-$$(date +%F).sql.gz
	$(COMPOSE) exec -T neo4j neo4j-admin database dump neo4j --to-stdout > backups/graph-$$(date +%F).dump
	@echo "wrote backups/"

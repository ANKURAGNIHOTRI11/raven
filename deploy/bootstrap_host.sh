#!/usr/bin/env bash
# Prepare a bare-metal Ubuntu 22.04 host with a supported NVIDIA GPU to run RAVEN.
# Idempotent: safe to re-run.
set -euo pipefail

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
need_root() { [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }; }
need_root

log "Checking the NVIDIA driver"
if ! command -v nvidia-smi >/dev/null; then
  echo "nvidia-smi not found. Install a supported NVIDIA driver before running this bootstrap."
  echo "The default vLLM CUDA 12.9 image expects NVIDIA Linux driver 575.51.03 or newer."
  exit 1
fi
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv

DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1)
MIN_DRIVER_VERSION=575.51.03
LOWEST_VERSION=$(printf '%s\n' "$MIN_DRIVER_VERSION" "$DRIVER_VERSION" | sort -V | head -n1)
if [[ "$LOWEST_VERSION" != "$MIN_DRIVER_VERSION" ]]; then
  echo "Driver $DRIVER_VERSION is older than the supported CUDA 12.9 baseline ($MIN_DRIVER_VERSION)."
  echo "Upgrade the NVIDIA driver and reboot before running this bootstrap."
  exit 1
fi

log "Installing Docker Engine"
if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

log "Installing the NVIDIA Container Toolkit"
if ! command -v nvidia-ctk >/dev/null; then
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
    > /etc/apt/sources.list.d/nvidia-container-toolkit.list
  apt-get update
  apt-get install -y nvidia-container-toolkit
fi
nvidia-ctk runtime configure --runtime=docker
systemctl restart docker

log "Kernel settings for OpenSearch and Neo4j"
sysctl -w vm.max_map_count=262144
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
sysctl -w fs.file-max=1048576

log "Verifying GPU access from a container"
docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi -L

log "Host is ready. Next: make env, edit optional .env settings, then make up"

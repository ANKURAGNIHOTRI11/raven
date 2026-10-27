#!/usr/bin/env bash
# Prepare a bare-metal Ubuntu 22.04 host with a supported NVIDIA GPU to run RAVEN.
# Idempotent: safe to re-run.
set -euo pipefail

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
need_root() { [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }; }
need_root

log "Checking the NVIDIA driver"
if ! command -v nvidia-smi >/dev/null; then
  echo "nvidia-smi not found. Install a supported NVIDIA driver (CUDA 12.4 requires driver 550 or newer):"
  echo "  apt-get install -y nvidia-driver-560-server && reboot"
  exit 1
fi
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv

DRIVER_MAJOR=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | cut -d. -f1)
if (( DRIVER_MAJOR < 550 )); then
  echo "Driver $DRIVER_MAJOR is too old for Hopper CUDA 12.4 containers. Upgrade to 550+."
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

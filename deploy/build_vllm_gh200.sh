#!/usr/bin/env bash
# Builds vllm-openai natively for Grace-Hopper (aarch64 + Hopper sm_90).
set -euo pipefail

VLLM_TAG="${VLLM_TAG:-v0.11.1}"
IMAGE_TAG="raven/vllm-gh200:local"
WORKDIR="$(mktemp -d)"

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "This host is not aarch64 ($(uname -m)) - you don't need this script," >&2
  echo "the standard vllm/vllm-openai image already targets your architecture." >&2
  exit 1
fi

echo "==> cloning vllm @ ${VLLM_TAG} into ${WORKDIR}"
git clone --depth 1 --branch "${VLLM_TAG}" https://github.com/vllm-project/vllm.git "${WORKDIR}/vllm"
cd "${WORKDIR}/vllm"

echo "==> building ${IMAGE_TAG} (native aarch64, no QEMU needed on this host)"
DOCKER_BUILDKIT=1 docker build . \
  --file docker/Dockerfile \
  --target vllm-openai \
  --platform linux/arm64 \
  -t "${IMAGE_TAG}" \
  --build-arg max_jobs="$(nproc)" \
  --build-arg nvcc_threads=2 \
  --build-arg torch_cuda_arch_list="9.0+PTX" \
  --build-arg TORCH_CUDA_ARCH_LIST="9.0a" \
  --build-arg RUN_WHEEL_CHECK=false

echo
echo "==> built ${IMAGE_TAG}"
docker image inspect "${IMAGE_TAG}" --format '    arch: {{.Architecture}}  size: {{.Size}} bytes'
echo "==> cleaning up ${WORKDIR}"
rm -rf "${WORKDIR}"
echo "==> done - 'make up' will now use this image for the vllm service"

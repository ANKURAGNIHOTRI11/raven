# Shared base for the GPU-side RAVEN workers (H200 / sm_90, CUDA 12.4).
FROM nvidia/cuda:12.4.1-cudnn-runtime-ubuntu22.04

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    HF_HOME=/models \
    TORCH_CUDA_ARCH_LIST="9.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-dev python3-pip build-essential curl ca-certificates git \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip setuptools wheel
# Hopper-class wheels. Pinned so a rebuild cannot silently change the kernel set.
RUN python -m pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cu124

COPY libs/raven_common /opt/raven_common
RUN python -m pip install /opt/raven_common

RUN useradd -m -u 10001 raven && mkdir -p /models && chown raven:raven /models
WORKDIR /app

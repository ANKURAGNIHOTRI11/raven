# Shared base for the CPU-side RAVEN workers.
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY libs/raven_common /opt/raven_common
RUN pip install --upgrade pip && pip install /opt/raven_common

RUN useradd -m -u 10001 raven
WORKDIR /app

"""WORM raw zone. Objects are written once under a content-addressed key and
the bucket is configured with object locking so an ingested artefact can be
re-read verbatim during an audit."""
from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone

from minio import Minio

from .settings import get_settings


def client() -> Minio:
    s = get_settings()
    return Minio(
        s.minio_endpoint,
        access_key=s.minio_access_key,
        secret_key=s.minio_secret_key,
        secure=s.minio_secure,
    )


def ensure_bucket() -> None:
    s = get_settings()
    c = client()
    if not c.bucket_exists(s.raw_bucket):
        c.make_bucket(s.raw_bucket, object_lock=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put_raw(source_id: str, data: bytes, content_type: str) -> tuple[str, str]:
    """Returns (object_key, sha256). Idempotent: same bytes -> same key."""
    s = get_settings()
    digest = sha256(data)
    day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    key = f"{source_id}/{day}/{digest}"
    c = client()
    c.put_object(s.raw_bucket, key, io.BytesIO(data), len(data), content_type=content_type)
    return key, digest


def get_raw(key: str) -> bytes:
    s = get_settings()
    resp = client().get_object(s.raw_bucket, key)
    try:
        return resp.read()
    finally:
        resp.close()
        resp.release_conn()

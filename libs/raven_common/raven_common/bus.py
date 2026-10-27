"""Thin async Kafka/Redpanda helpers with schema validation at the edge."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any, TypeVar

import orjson
import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from pydantic import BaseModel, ValidationError

from .metrics import ERRORS, MESSAGES_IN, MESSAGES_OUT
from .settings import get_settings

log = structlog.get_logger()
T = TypeVar("T", bound=BaseModel)


def _dumps(value: Any) -> bytes:
    return orjson.dumps(value, default=str)


class Producer:
    def __init__(self, service: str) -> None:
        self.service = service
        self._p: AIOKafkaProducer | None = None

    async def start(self) -> "Producer":
        s = get_settings()
        self._p = AIOKafkaProducer(
            bootstrap_servers=s.kafka_bootstrap,
            value_serializer=_dumps,
            key_serializer=lambda k: k.encode() if isinstance(k, str) else k,
            enable_idempotence=True,
            acks="all",
            compression_type="gzip",
        )
        await self._p.start()
        return self

    async def stop(self) -> None:
        if self._p:
            await self._p.stop()

    async def send(self, topic: str, model: BaseModel, key: str | None = None) -> None:
        assert self._p is not None, "producer not started"
        await self._p.send_and_wait(topic, model.model_dump(mode="json"), key=key)
        MESSAGES_OUT.labels(self.service, topic).inc()


async def consume(
    topics: list[str],
    group: str,
    schema: type[T],
    service: str,
    on_invalid: Callable[[dict, Exception], Any] | None = None,
) -> AsyncIterator[T]:
    """Yield only messages that satisfy the contract. Invalid payloads are
    handed to on_invalid (normally: route to quarantine) and dropped."""
    s = get_settings()
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=s.kafka_bootstrap,
        group_id=f"{s.kafka_group_prefix}.{group}",
        value_deserializer=orjson.loads,
        enable_auto_commit=True,
        auto_offset_reset="earliest",
        max_poll_interval_ms=900_000,
    )
    await consumer.start()
    try:
        async for msg in consumer:
            MESSAGES_IN.labels(service, msg.topic).inc()
            try:
                yield schema.model_validate(msg.value)
            except ValidationError as exc:
                ERRORS.labels(service, "schema").inc()
                log.warning("contract_violation", topic=msg.topic, error=str(exc)[:400])
                if on_invalid:
                    res = on_invalid(msg.value, exc)
                    if asyncio.iscoroutine(res):
                        await res
    finally:
        await consumer.stop()


async def ensure_topics(topics: list[str], partitions: int = 3) -> None:
    s = get_settings()
    admin = AIOKafkaAdminClient(bootstrap_servers=s.kafka_bootstrap)
    await admin.start()
    try:
        await admin.create_topics(
            [NewTopic(t, num_partitions=partitions, replication_factor=1) for t in topics]
        )
    except Exception as exc:  # topics already exist on restart
        log.debug("topic_create_skipped", error=str(exc)[:200])
    finally:
        await admin.close()


async def wait_for_bus(attempts: int = 60, delay: float = 2.0) -> None:
    s = get_settings()
    for i in range(attempts):
        try:
            p = AIOKafkaProducer(bootstrap_servers=s.kafka_bootstrap)
            await p.start()
            await p.stop()
            return
        except Exception:
            await asyncio.sleep(delay)
    raise RuntimeError(f"bus unreachable at {s.kafka_bootstrap}")

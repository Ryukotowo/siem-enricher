"""Коннекторы Kafka: подписка на поток событий и публикация обогащённых событий."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Mapping

from siem_enricher.connectors.base import (
    SinkConnector,
    SourceConnector,
    register_sink,
    register_source,
)
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.event import NormalizedEvent

logger = get_logger("connectors.kafka")

INSTALL_HINT = "Для коннекторов Kafka требуется библиотека aiokafka: pip install 'siem-enricher[kafka]'"


def _consumer_options(options: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if options.get("security_protocol"):
        result["security_protocol"] = str(options["security_protocol"])
    if options.get("sasl_mechanism"):
        result["sasl_mechanism"] = str(options["sasl_mechanism"])
    if options.get("sasl_username"):
        result["sasl_plain_username"] = str(options["sasl_username"])
        result["sasl_plain_password"] = str(options.get("sasl_password", ""))
    return result


@register_source("kafka")
class KafkaSource(SourceConnector):
    """Источник событий из Kafka с ручным подтверждением смещений."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        normalizer: Any = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, normalizer, metrics, name or "kafka")
        self.bootstrap = str(self._option("bootstrap_servers", "localhost:9092"))
        topics = self._option("topics") or self._option("topic") or "siem.raw.events"
        self.topics = [topics] if isinstance(topics, str) else list(topics)
        self.group_id = str(self._option("group_id", "siem-enricher"))
        self.auto_offset_reset = str(self._option("auto_offset_reset", "latest"))
        self.poll_timeout = float(self._option("poll_timeout_ms", 1000)) / 1000.0
        self._consumer: Any = None
        self._stopping = False

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(INSTALL_HINT) from exc
        self._consumer = AIOKafkaConsumer(
            *self.topics,
            bootstrap_servers=self.bootstrap,
            group_id=self.group_id,
            auto_offset_reset=self.auto_offset_reset,
            enable_auto_commit=False,
            value_deserializer=lambda raw: json.loads(raw.decode("utf-8")) if raw else None,
            **_consumer_options(self.options),
        )
        await self._consumer.start()
        self._started = True
        logger.info("Источник Kafka готов", extra={"topics": self.topics, "group_id": self.group_id})

    async def stop(self) -> None:
        self._stopping = True
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        self._started = False

    async def stream(self) -> AsyncIterator[NormalizedEvent]:
        if self._consumer is None:
            await self.start()
        while not self._stopping:
            try:
                batches = await self._consumer.getmany(timeout_ms=int(self.poll_timeout * 1000))
            except Exception as exc:  # noqa: BLE001 - переживаем обрывы соединения
                logger.error("Ошибка чтения из Kafka", extra={"reason": str(exc)})
                if self.metrics is not None:
                    self.metrics.source_errors.inc({"source": self.name})
                await asyncio.sleep(1.0)
                continue
            for messages in batches.values():
                for message in messages:
                    document = message.value
                    if not isinstance(document, Mapping):
                        logger.warning("Пропущено сообщение Kafka: ожидался объект JSON",
                                       extra={"topic": message.topic, "offset": message.offset})
                        if self.metrics is not None:
                            self.metrics.events_consumed.inc({"source": self.name, "status": "error"})
                        continue
                    if self.metrics is not None:
                        self.metrics.events_consumed.inc({"source": self.name, "status": "ok"})
                    yield self.normalize(document)

    async def ack(self, event: NormalizedEvent) -> None:
        """Зафиксировать смещения обработанных сообщений."""
        if self._consumer is not None:
            try:
                await self._consumer.commit()
            except Exception as exc:  # noqa: BLE001
                logger.error("Ошибка фиксации смещения Kafka", extra={"reason": str(exc)})

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"topics": self.topics, "group_id": self.group_id})
        return info


@register_sink("kafka")
class KafkaSink(SinkConnector):
    """Публикация обогащённых событий в Kafka."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "kafka")
        self.bootstrap = str(self._option("bootstrap_servers", "localhost:9092"))
        self.topic = str(self._option("topic", "siem.enriched.events"))
        self.acks = str(self._option("acks", "all"))
        self.linger_ms = int(self._option("linger_ms", 20))
        self._producer: Any = None

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(INSTALL_HINT) from exc
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap,
            acks=self.acks,
            linger_ms=self.linger_ms,
            value_serializer=lambda value: json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"),
            **_consumer_options(self.options),
        )
        await self._producer.start()
        self._started = True
        logger.info("Приёмник Kafka готов", extra={"topic": self.topic})

    async def send(self, document: dict[str, Any]) -> bool:
        if self._producer is None:
            await self.start()
        try:
            await self._producer.send_and_wait(self.topic, document, key=str(document.get("event_id")).encode())
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка отправки в Kafka", extra={"topic": self.topic, "reason": str(exc)})
            if self.metrics is not None:
                self.metrics.sink_sent.inc({"sink": self.name, "status": "error"})
            return False
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"})
        return True

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None
        self._started = False

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"topic": self.topic, "bootstrap_servers": self.bootstrap})
        return info

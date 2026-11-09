"""Среда выполнения сервиса: конвейер «источник -> обогатитель -> приёмник»."""

from __future__ import annotations

import os

import asyncio
import time
from pathlib import Path
from typing import Any, Sequence

from siem_enricher.config import AppConfig, ConnectorConfig
from siem_enricher.connectors import SinkConnector, SourceConnector, build_sink, build_source
from siem_enricher.connectors.file_replay import FileJsonlSink, FileReplaySource
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.logging_setup import event_context, get_logger
from siem_enricher.metrics import ServiceMetrics, service_metrics
from siem_enricher.models.enrichment import EnrichedEvent
from siem_enricher.version import VERSION

logger = get_logger("service.runtime")


class EnrichmentRuntime:
    """Управляет жизненным циклом конвейера обогащения."""

    def __init__(
        self,
        config: AppConfig,
        pipeline: EnrichmentPipeline | None = None,
        metrics: ServiceMetrics | None = None,
    ) -> None:
        self.config = config
        self.metrics = metrics or service_metrics()
        self.pipeline = pipeline or EnrichmentPipeline.from_config(config, metrics=self.metrics)
        self.started_at: float | None = None
        self._stopping = False
        self.processed = 0
        self.failed = 0

    @property
    def stopping(self) -> bool:
        return self._stopping

    def request_stop(self) -> None:
        """Запросить корректное завершение обработки (graceful shutdown)."""
        self._stopping = True
        logger.info("Запрошена остановка конвейера", extra={"processed": self.processed})

    async def run(self, max_events: int | None = None, flush_every: int = 100) -> dict[str, Any]:
        """Запустить непрерывную обработку событий источника."""
        source = build_source(self.config.source, normalizer=self.pipeline.normalize, metrics=self.metrics)
        sink = build_sink(self.config.sink, metrics=self.metrics)
        logger.info(
            "Запуск конвейера обогащения",
            extra={"source": source.describe(), "sink": sink.describe(), "version": VERSION},
        )
        self.started_at = time.monotonic()
        monitor = asyncio.create_task(self._monitor_uptime())
        try:
            async with source, sink:
                async for event in source.stream():
                    if self._stopping:
                        break
                    await self._handle_event(event, source, sink)
                    if max_events and self.processed >= max_events:
                        logger.info("Достигнут предел обработанных событий", extra={"max_events": max_events})
                        break
                    if flush_every and self.processed % flush_every == 0:
                        await sink.flush()
        finally:
            monitor.cancel()
            try:
                await sink.flush()
            except Exception as exc:  # noqa: BLE001
                logger.error("Ошибка финальной отправки буфера", extra={"reason": str(exc)})
        return self.stats()

    async def _handle_event(
        self,
        event: Any,
        source: SourceConnector,
        sink: SinkConnector,
    ) -> bool:
        """Обогатить событие и вернуть его в SIEM."""
        with event_context(event.event_id):
            try:
                enriched = self.pipeline.enrich(event)
            except Exception as exc:  # noqa: BLE001 - одно событие не должно останавливать конвейер
                self.failed += 1
                self.metrics.events_enriched.inc({"status": "error"})
                logger.exception("Ошибка обогащения события", extra={"reason": str(exc)})
                return False

            document = enriched.siem_document()
            try:
                delivered = await sink.send(document)
            except Exception as exc:  # noqa: BLE001
                delivered = False
                self.metrics.sink_sent.inc({"sink": sink.name, "status": "error"})
                logger.error("Ошибка приёмника", extra={"sink": sink.name, "reason": str(exc)})

            if delivered:
                self.processed += 1
                await source.ack(event)
            else:
                self.failed += 1
                logger.warning("Обогащённое событие не доставлено в SIEM", extra={"sink": sink.name})
            return delivered

    async def _monitor_uptime(self) -> None:
        """Периодически обновлять метрику времени работы."""
        while True:
            if self.started_at is not None:
                self.metrics.uptime_seconds.set(time.monotonic() - self.started_at)
            await asyncio.sleep(5.0)

    def stats(self) -> dict[str, Any]:
        """Итоги работы конвейера (для CLI и ``/v1/version``)."""
        elapsed = (time.monotonic() - self.started_at) if self.started_at else 0.0
        return {
            "processed": self.processed,
            "failed": self.failed,
            "elapsed_seconds": round(elapsed, 3),
            "throughput_per_second": round(self.processed / elapsed, 2) if elapsed > 0 else 0.0,
            "source": self.config.source.type,
            "sink": self.config.sink.type,
            "policy_mode": self.config.policy.mode,
        }

    def close(self) -> None:
        self.pipeline.close()

    async def replay(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
        limit: int | None = None,
        apply_policies: bool = True,
        collect_documents: bool = False,
        summary_limit: int = 5000,
    ) -> dict[str, Any]:
        """Однократно обогатить файл событий (используется CLI и измерениями ВКР)."""
        source = FileReplaySource(
            {"path": str(input_path), "format": "auto", "follow": False, "loop": False},
            normalizer=self.pipeline.normalize,
            metrics=self.metrics,
            name="file_replay",
        )
        sink: SinkConnector | None = None
        if output_path is not None:
            sink = FileJsonlSink({"path": str(output_path), "mode": "overwrite"}, metrics=self.metrics)

        collected: list[EnrichedEvent] = []
        documents: list[dict[str, Any]] = []
        started = time.perf_counter()
        await source.start()
        if sink is not None:
            await sink.start()
        try:
            async def process_batch(items: list[Any]) -> None:
                paths: list[str] = []
                for item in items:
                    for file_item in (item.files or []):
                        path = getattr(file_item, "path", None)
                        if path:
                            paths.append(str(path))
                if paths:
                    self.pipeline.warm(paths)
                for item in items:
                    if limit and self.processed >= limit:
                        break
                    enriched = self.pipeline.enrich(item, apply_policies=apply_policies)
                    document = enriched.siem_document()
                    if sink is not None and not await sink.send(document):
                        self.failed += 1
                    else:
                        self.processed += 1
                    if len(collected) < summary_limit:
                        collected.append(enriched)
                        if collect_documents:
                            documents.append(document)

            batch: list[Any] = []
            batch_size = int(os.environ.get("SIEM_BATCH_SIZE", "64"))
            async for event in source.stream():
                batch.append(event)
                if len(batch) < batch_size:
                    continue
                await process_batch(batch)
                batch.clear()
                if limit and self.processed >= limit:
                    break
            if batch and not (limit and self.processed >= limit):
                await process_batch(batch)
        finally:
            if sink is not None:
                await sink.flush()
                await sink.stop()
            await source.stop()

        summary = self.pipeline.summarize(collected) if collected else {
            "events": self.processed,
            "sensitivity_levels": {},
            "risk_severities": {},
            "triggered_rules": {},
            "mean_risk_score": 0.0,
            "max_risk_score": 0.0,
            "mean_duration_ms": 0.0,
            "policy_decision": "allow",
        }
        summary.update(
            {
                "input": str(input_path),
                "output": str(output_path) if output_path else None,
                "processed": self.processed,
                "failed": self.failed,
                "elapsed_seconds": round(time.perf_counter() - started, 3),
                "throughput_per_second": round(
                    self.processed / max(1e-9, time.perf_counter() - started), 2
                ),
                "policy_mode": self.config.policy.mode,
                "apply_policies": apply_policies,
                "summary_events": len(collected),
                "summary_limit": summary_limit,
            }
        )
        if collect_documents:
            summary["documents"] = documents
        return summary

    async def enrich_documents(
        self,
        documents: Sequence[dict[str, Any]],
        source: str = "api",
        apply_policies: bool = True,
    ) -> list[EnrichedEvent]:
        """Обогатить набор «сырых» документов (пакетный режим API)."""
        results: list[EnrichedEvent] = []
        for document in documents:
            event = self.pipeline.normalize(source, document)
            results.append(self.pipeline.enrich(event, apply_policies=apply_policies))
        return results


def build_runtime(
    config: AppConfig,
    metrics: ServiceMetrics | None = None,
    in_memory_store: bool = False,
) -> EnrichmentRuntime:
    """Собрать среду выполнения по конфигурации."""
    pipeline = EnrichmentPipeline.from_config(config, metrics=metrics, in_memory_store=in_memory_store)
    return EnrichmentRuntime(config, pipeline=pipeline, metrics=metrics)


def source_config(connector_type: str, options: dict[str, Any] | None = None) -> ConnectorConfig:
    """Вспомогательная функция для тестов: описание источника."""
    return ConnectorConfig(type=connector_type, options=dict(options or {}))


__all__ = ["EnrichmentRuntime", "build_runtime", "source_config"]

"""Файловые коннекторы: воспроизведение событий из файла и запись результата."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence

from siem_enricher.connectors.base import (
    SinkConnector,
    SourceConnector,
    register_sink,
    register_source,
)
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.event import NormalizedEvent

logger = get_logger("connectors.file")


@register_source("file_replay")
class FileReplaySource(SourceConnector):
    """Воспроизведение событий из JSONL/JSON-файла."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        normalizer: Any = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, normalizer, metrics, name or "file_replay")
        self.path = Path(str(self._option("path", "events.jsonl")))
        self.format = str(self._option("format", "auto")).lower()
        self.follow = bool(self._option("follow", False))
        self.loop = bool(self._option("loop", False))
        self.interval = max(0.0, float(self._option("interval_ms", 200)) / 1000.0)
        self.encoding = str(self._option("encoding", "utf-8"))
        max_events = self._option("max_events")
        self.max_events = int(max_events) if max_events else 0
        self._stopping = False

    async def stop(self) -> None:
        self._stopping = True
        await super().stop()

    async def stream(self) -> AsyncIterator[NormalizedEvent]:
        emitted = 0
        if self.follow and self._detect_format() == "jsonl":
            async for event in self._stream_follow():
                yield event
                emitted += 1
                if self.max_events and emitted >= self.max_events:
                    return
            return

        while True:
            for document in self._load_all():
                if self._stopping:
                    return
                self._count_consumed()
                yield self.normalize(document)
                emitted += 1
                if self.max_events and emitted >= self.max_events:
                    return
            if not self.loop:
                return
            await asyncio.sleep(self.interval or 0.1)

    async def _stream_follow(self) -> AsyncIterator[NormalizedEvent]:
        """Режим «хвоста»: читать новые строки по мере появления."""
        if not self.path.exists():
            logger.info("Файл событий ещё не создан, ожидаю", extra={"path": str(self.path)})
        offset = 0
        while not self._stopping:
            if not self.path.exists():
                await asyncio.sleep(self.interval or 0.2)
                continue
            size = self.path.stat().st_size
            if size < offset:  # файл обрезан/перезаписан
                offset = 0
            if size == offset:
                await asyncio.sleep(self.interval or 0.2)
                continue
            with self.path.open("r", encoding=self.encoding, errors="replace") as handle:
                handle.seek(offset)
                for line in handle:
                    if not line.endswith("\n"):  # неполная строка — вернёмся к ней позже
                        break
                    offset += len(line.encode(self.encoding, errors="replace"))
                    stripped = line.strip()
                    if not stripped:
                        continue
                    document = self._parse_line(stripped)
                    if document is None:
                        continue
                    self._count_consumed()
                    yield self.normalize(document)

    def _detect_format(self) -> str:
        if self.format in {"jsonl", "ndjson"}:
            return "jsonl"
        if self.format == "json":
            return "json"
        suffix = self.path.suffix.lower()
        if suffix in {".jsonl", ".ndjson", ".log"}:
            return "jsonl"
        if suffix == ".json":
            return "json"
        return "jsonl"

    def _load_all(self) -> list[Mapping[str, Any]]:
        if not self.path.exists():
            raise FileNotFoundError(f"Файл событий не найден: {self.path}")
        text = self.path.read_text(encoding=self.encoding, errors="replace")
        if self._detect_format() == "json":
            return self._parse_json(text)
        documents: list[Mapping[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            document = self._parse_line(stripped, number)
            if document is not None:
                documents.append(document)
        return documents

    def _parse_json(self, text: str) -> list[Mapping[str, Any]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self._count_error(f"некорректный JSON: {exc}")
            return []
        if isinstance(data, list):
            return [item for item in data if isinstance(item, Mapping)]
        if isinstance(data, Mapping):
            for key in ("events", "hits", "documents", "items", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, Mapping)]
            return [data]
        self._count_error("ожидался объект или массив JSON")
        return []

    def _parse_line(self, line: str, number: int | None = None) -> Mapping[str, Any] | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            self._count_error(f"строка {number or '?'}: {exc}")
            return None
        if not isinstance(data, Mapping):
            self._count_error(f"строка {number or '?'}: ожидался объект JSON")
            return None
        return data

    def _count_consumed(self) -> None:
        if self.metrics is not None:
            self.metrics.events_consumed.inc({"source": self.name, "status": "ok"})

    def _count_error(self, reason: str) -> None:
        logger.warning("Ошибка разбора события", extra={"path": str(self.path), "reason": reason})
        if self.metrics is not None:
            self.metrics.source_errors.inc({"source": self.name})
            self.metrics.events_consumed.inc({"source": self.name, "status": "error"})


@register_sink("file_jsonl")
class FileJsonlSink(SinkConnector):
    """Запись обогащённых событий в файл JSON Lines."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "file_jsonl")
        self.path = Path(str(self._option("path", "var/enriched_events.jsonl")))
        self.mode = str(self._option("mode", "append")).lower()
        self.pretty = bool(self._option("pretty", False))
        self._handle: Any = None
        self._truncated = False

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._started = True

    async def send(self, document: dict[str, Any]) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self._handle is None:
                open_mode = "w" if self.mode == "overwrite" and not self._truncated else "a"
                self._handle = self.path.open(open_mode, encoding="utf-8")
                self._truncated = True
            payload = json.dumps(document, ensure_ascii=False, indent=2 if self.pretty else None, default=str)
            self._handle.write(payload + "\n")
            self._handle.flush()
        except OSError as exc:
            logger.error("Ошибка записи обогащённого события", extra={"path": str(self.path), "reason": str(exc)})
            if self.metrics is not None:
                self.metrics.sink_sent.inc({"sink": self.name, "status": "error"})
            return False
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"})
        return True

    async def send_many(self, documents: Sequence[dict[str, Any]]) -> int:
        sent = 0
        for document in documents:
            if await self.send(document):
                sent += 1
        return sent

    async def stop(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self._started = False

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"path": str(self.path), "mode": self.mode})
        return info


@register_sink("console")
class ConsoleSink(SinkConnector):
    """Вывод обогащённых событий в стандартный поток — удобно для демонстрации."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "console")
        self.indent = 2 if bool(self._option("pretty", True)) else None
        limit = self._option("max_events")
        self.max_events = int(limit) if limit else 0
        self._printed = 0
        self.stream = sys.stdout

    async def send(self, document: dict[str, Any]) -> bool:
        if self.max_events and self._printed >= self.max_events:
            return True
        self.stream.write(json.dumps(document, ensure_ascii=False, indent=self.indent, default=str) + "\n")
        self.stream.flush()
        self._printed += 1
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"})
        return True


@register_sink("null")
class NullSink(SinkConnector):
    """Приёмник-«заглушка»: используется в измерениях производительности конвейера."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "null")
        self.counter = 0

    async def send(self, document: dict[str, Any]) -> bool:
        self.counter += 1
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"})
        return True

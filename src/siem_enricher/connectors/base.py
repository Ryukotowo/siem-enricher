"""Базовые интерфейсы коннекторов к SIEM (источник событий и приёмник результатов)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from typing import Any

from siem_enricher.config import ConnectorConfig
from siem_enricher.extractor import MetadataExtractor
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.event import NormalizedEvent

logger = get_logger("connectors")

Normalizer = Callable[[str, Mapping[str, Any]], NormalizedEvent]


class Connector(ABC):
    """Общая часть коннекторов."""

    type_name = "abstract"
    kind = "connector"

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        self.options: dict[str, Any] = dict(options or {})
        self.metrics = metrics
        self.name = name or self.type_name
        self._started = False

    @property
    def started(self) -> bool:
        return self._started

    def describe(self) -> dict[str, Any]:
        """Описание коннектора для логов и ответа ``/v1/version``."""
        return {"type": self.type_name, "name": self.name, "kind": self.kind}

    def _option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


class SourceConnector(Connector):
    """Источник событий SIEM."""

    kind = "source"

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        normalizer: Normalizer | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name)
        self._normalizer = normalizer
        self._fallback_extractor = MetadataExtractor()

    def set_normalizer(self, normalizer: Normalizer) -> None:
        """Передать функцию нормализации события (обычно ``pipeline.normalize``)."""
        self._normalizer = normalizer

    def normalize(self, document: Mapping[str, Any]) -> NormalizedEvent:
        """Привести «сырое» событие к канонической модели."""
        if self._normalizer is not None:
            return self._normalizer(self.name, document)
        return self._fallback_extractor.normalize(self.name, document)

    async def start(self) -> None:
        """Подготовить соединение с источником."""
        self._started = True

    async def stop(self) -> None:
        """Освободить ресурсы."""
        self._started = False

    @abstractmethod
    def stream(self) -> AsyncIterator[NormalizedEvent]:
        """Асинхронный поток событий источника."""

    async def ack(self, event: NormalizedEvent) -> None:
        """Подтвердить обработку события (коммит смещения/удаление из очереди)."""

    async def __aenter__(self) -> SourceConnector:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.stop()


class SinkConnector(Connector):
    """Приёмник обогащённых событий (обратный коннектор в SIEM)."""

    kind = "sink"

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        """Освободить ресурсы."""

    @abstractmethod
    async def send(self, document: dict[str, Any]) -> bool:
        """Отправить один обогащённый документ. Возвращает признак успеха."""

    async def send_many(self, documents: Sequence[dict[str, Any]]) -> int:
        """Отправить пакет документов. Возвращает число успешно отправленных."""
        sent = 0
        for document in documents:
            if await self.send(document):
                sent += 1
        return sent

    async def flush(self) -> bool:
        """Дослать буферизованные документы. ``True`` — всё доставлено."""
        return True

    async def __aenter__(self) -> SinkConnector:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.flush()
        await self.stop()


SOURCE_TYPES: dict[str, type[SourceConnector]] = {}
SINK_TYPES: dict[str, type[SinkConnector]] = {}


def register_source(name: str) -> Callable[[type[SourceConnector]], type[SourceConnector]]:
    """Декоратор регистрации типа источника."""

    def decorator(cls: type[SourceConnector]) -> type[SourceConnector]:
        cls.type_name = name
        SOURCE_TYPES[name] = cls
        return cls

    return decorator


def register_sink(name: str) -> Callable[[type[SinkConnector]], type[SinkConnector]]:
    """Декоратор регистрации типа приёмника."""

    def decorator(cls: type[SinkConnector]) -> type[SinkConnector]:
        cls.type_name = name
        SINK_TYPES[name] = cls
        return cls

    return decorator


def build_source(
    config: ConnectorConfig,
    normalizer: Normalizer | None = None,
    metrics: ServiceMetrics | None = None,
    name: str | None = None,
) -> SourceConnector:
    """Создать источник по конфигурации ``source``."""
    cls = SOURCE_TYPES.get(config.type)
    if cls is None:
        raise ValueError(
            f"Неизвестный тип источника {config.type!r}. Доступны: {', '.join(sorted(SOURCE_TYPES))}"
        )
    if cls is MultiSource:  # pragma: no cover - защита от рекурсии
        raise ValueError("multi не может использоваться как тип источника")
    return cls(config.options, normalizer=normalizer, metrics=metrics, name=name)  # type: ignore[call-arg]


def build_sink(
    config: ConnectorConfig,
    metrics: ServiceMetrics | None = None,
    name: str | None = None,
) -> SinkConnector:
    """Создать приёмник по конфигурации ``sink`` (поддерживается ``multi``)."""
    if config.type == "multi":
        return MultiSink(config.options, metrics=metrics, name=name)
    cls = SINK_TYPES.get(config.type)
    if cls is None:
        raise ValueError(
            f"Неизвестный тип приёмника {config.type!r}. Доступны: {', '.join(sorted(SINK_TYPES))}"
        )
    return cls(config.options, metrics=metrics, name=name)  # type: ignore[call-arg]


def available_sources() -> list[str]:
    return sorted(SOURCE_TYPES)


def available_sinks() -> list[str]:
    return sorted([*SINK_TYPES, "multi"])


class MultiSink(SinkConnector):
    """Приёмник-«разветвитель»: отправляет документ сразу в несколько приёмников."""

    type_name = "multi"
    kind = "sink"

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name)
        definitions = self._option("sinks") or []
        if not isinstance(definitions, list) or not definitions:
            raise ValueError("Приёмник multi требует непустой список options.sinks")
        self.sinks: list[SinkConnector] = []
        for index, definition in enumerate(definitions):
            if not isinstance(definition, Mapping) or "type" not in definition:
                raise ValueError(f"Элемент options.sinks[{index}] должен содержать поле type")
            connector_config = ConnectorConfig(
                type=str(definition["type"]),
                options=dict(definition.get("options") or {}),
            )
            self.sinks.append(
                build_sink(connector_config, metrics=metrics, name=f"{self.name}:{connector_config.type}")
            )

    async def start(self) -> None:
        for sink in self.sinks:
            await sink.start()
        self._started = True

    async def stop(self) -> None:
        for sink in self.sinks:
            await sink.stop()
        self._started = False

    async def send(self, document: dict[str, Any]) -> bool:
        results = []
        for sink in self.sinks:
            try:
                results.append(await sink.send(document))
            except Exception as exc:  # noqa: BLE001 - сбой одного приёмника не блокирует остальные
                logger.error("Ошибка приёмника", extra={"sink": sink.name, "reason": str(exc)})
                results.append(False)
        return all(results)

    async def flush(self) -> bool:
        results = [await sink.flush() for sink in self.sinks]
        return all(results)

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info["sinks"] = [sink.describe() for sink in self.sinks]
        return info


# MultiSource оставлен как явный маркер недопустимого типа в build_source
class MultiSource(SourceConnector):  # pragma: no cover - используется только для проверки
    """Заглушка, запрещающая использовать ``multi`` в качестве источника."""

    def stream(self) -> AsyncIterator[NormalizedEvent]:  # type: ignore[override]
        raise NotImplementedError

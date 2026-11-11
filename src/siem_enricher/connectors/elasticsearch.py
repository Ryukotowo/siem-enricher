"""Коннекторы к Elasticsearch/OpenSearch (в том числе Wazuh Indexer)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any

from siem_enricher.connectors.base import (
    SinkConnector,
    SourceConnector,
    register_sink,
    register_source,
)
from siem_enricher.connectors.checkpoint import CheckpointStore
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.event import NormalizedEvent

logger = get_logger("connectors.elasticsearch")

INSTALL_HINT = "Для коннекторов Elasticsearch требуется библиотека elasticsearch: pip install 'siem-enricher[es]'"


def _build_client_options(options: Mapping[str, Any]) -> dict[str, Any]:
    """Собрать параметры клиента Elasticsearch из опций коннектора."""
    hosts = options.get("hosts") or options.get("url") or options.get("host")
    if isinstance(hosts, str):
        hosts = [hosts]
    client_options: dict[str, Any] = {"hosts": list(hosts or ["http://localhost:9200"])}
    if options.get("username"):
        client_options["basic_auth"] = (str(options["username"]), str(options.get("password", "")))
    if options.get("api_key"):
        client_options["api_key"] = options["api_key"]
    if "verify_certs" in options:
        client_options["verify_certs"] = bool(options["verify_certs"])
    if options.get("ca_certs"):
        client_options["ca_certs"] = str(options["ca_certs"])
    if options.get("request_timeout"):
        client_options["request_timeout"] = float(options["request_timeout"])
    # Клиент elasticsearch 8.x по умолчанию отправляет заголовок
    # application/vnd.elasticsearch+json; compatible-with=8, который OpenSearch и Wazuh
    # Indexer отвергают с ошибкой 406. Явные заголовки JSON включают совместимость.
    if not options.get("vendor_headers", False):
        client_options["headers"] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
    return client_options


def _create_client(options: Mapping[str, Any]):
    """Создать асинхронный клиент хранилища."""
    client_options = _build_client_options(options)
    try:
        from opensearchpy import AsyncOpenSearch
    except ImportError:
        try:
            from elasticsearch import AsyncElasticsearch  # noqa: F401  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(INSTALL_HINT) from exc
        return AsyncElasticsearch(**client_options)

    if "basic_auth" in client_options:
        client_options["http_auth"] = client_options.pop("basic_auth")
    if "request_timeout" in client_options:
        client_options.setdefault("timeout", client_options.pop("request_timeout"))
    client_options.pop("headers", None)
    return AsyncOpenSearch(**client_options)


@register_source("elasticsearch")
class ElasticsearchSource(SourceConnector):
    """Источник событий из индекса Elasticsearch/OpenSearch."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        normalizer: Any = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, normalizer, metrics, name or "elasticsearch")
        self.index = str(self._option("index", "siem-events-*"))
        self.batch_size = int(self._option("batch_size", 500))
        self.poll_interval = max(0.1, float(self._option("poll_interval_ms", 2000)) / 1000.0)
        self.timestamp_field = str(self._option("timestamp_field", "@timestamp"))
        self.from_now = bool(self._option("from_now", True))
        self.extra_query = self._option("query") or {}
        self.checkpoint = CheckpointStore(self._option("checkpoint_path", "var/state/checkpoint.json"))
        self.checkpoint_key = str(self._option("checkpoint_key", f"es:{self.index}"))
        self.metrics: ServiceMetrics | None = metrics
        self._client: Any = None
        self._stopping = False
        self._pending: dict[str, list[Any]] = {}

    async def start(self) -> None:
        try:
            from elasticsearch import AsyncElasticsearch  # noqa: F401
        except ImportError as exc:  # pragma: no cover - зависит от окружения
            raise RuntimeError(INSTALL_HINT) from exc
        self._client = _create_client(self.options)
        self._started = True
        logger.info("Источник Elasticsearch готов", extra={"index": self.index, "hosts": self.options.get("hosts")})

    async def stop(self) -> None:
        self._stopping = True
        if self._client is not None:
            await self._client.close()
            self._client = None
        self.checkpoint.save()
        self._started = False

    def _build_query(self, cursor_filter: Mapping[str, Any]) -> dict[str, Any]:
        must: list[dict[str, Any]] = []
        if self.extra_query:
            must.append(self.extra_query)
        if cursor_filter:
            must.append({"range": cursor_filter})
        return {"bool": {"must": must}} if must else {"match_all": {}}

    async def stream(self) -> AsyncIterator[NormalizedEvent]:
        if self._client is None:
            await self.start()
        search_after = self.checkpoint.get(self.checkpoint_key)
        if search_after is None and self.from_now:
            start = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
            cursor_filter: dict[str, Any] = {self.timestamp_field: {"gte": start}}
        elif isinstance(search_after, list):
            cursor_filter = {}
        else:
            cursor_filter = {}
            search_after = None

        while not self._stopping:
            body: dict[str, Any] = {
                "query": self._build_query(cursor_filter),
                "sort": [{self.timestamp_field: "asc"}, {"_id": "asc"}],
                "size": self.batch_size,
            }
            if search_after:
                body["search_after"] = search_after
            try:
                response = await self._client.search(index=self.index, body=body)
            except Exception as exc:  # noqa: BLE001 - источник должен переживать сбои связи
                logger.error("Ошибка опроса Elasticsearch", extra={"index": self.index, "reason": str(exc)})
                if self.metrics is not None:
                    self.metrics.source_errors.inc({"source": self.name})
                await asyncio.sleep(self.poll_interval)
                continue

            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                await asyncio.sleep(self.poll_interval)
                continue

            for hit in hits:
                document = dict(hit.get("_source") or {})
                document.setdefault("_id", hit.get("_id"))
                document.setdefault("_index", hit.get("_index"))
                if self.metrics is not None:
                    self.metrics.events_consumed.inc({"source": self.name, "status": "ok"})
                if hit.get("sort"):
                    self._pending[document["_id"]] = hit["sort"]
                    search_after = hit["sort"]
                yield self.normalize(document)

            self.checkpoint.set(self.checkpoint_key, search_after)
            self.checkpoint.save()

    async def ack(self, event: NormalizedEvent) -> None:
        """Сохранить позицию чтения после успешной обработки события."""
        sort_value = self._pending.pop(event.event_id, None)
        if sort_value is not None:
            self.checkpoint.update(self.checkpoint_key, sort_value)

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"index": self.index, "batch_size": self.batch_size})
        return info


@register_sink("elasticsearch")
class ElasticsearchSink(SinkConnector):
    """Запись обогащённых событий в индекс Elasticsearch/OpenSearch."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "elasticsearch")
        self.index = str(self._option("index", "siem-enriched-events-%Y.%m.%d"))
        self.batch_size = max(1, int(self._option("batch_size", 200)))
        self.pipeline = self._option("pipeline")
        self._client: Any = None
        self._buffer: list[dict[str, Any]] = []

    async def start(self) -> None:
        try:
            from elasticsearch import AsyncElasticsearch  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(INSTALL_HINT) from exc
        self._client = _create_client(self.options)
        self._started = True

    def _index_name(self) -> str:
        return datetime.now(tz=UTC).strftime(self.index) if "%" in self.index else self.index

    async def send(self, document: dict[str, Any]) -> bool:
        self._buffer.append(document)
        if len(self._buffer) >= self.batch_size:
            return await self.flush()
        return True

    async def flush(self) -> bool:
        """Записать буфер в индекс одним bulk-запросом."""
        if not self._buffer:
            return True
        if self._client is None:
            await self.start()
        try:
            from opensearchpy import helpers  # type: ignore[no-redef]
        except ImportError:
            try:
                from elasticsearch import helpers  # type: ignore[no-redef]
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(INSTALL_HINT) from exc

        actions = [
            {
                "_index": self._index_name(),
                "_id": document.get("event_id"),
                "_source": document,
                **({"_op_type": "index"} if not self.pipeline else {}),
            }
            for document in self._buffer
        ]
        count = len(actions)
        try:
            success, errors = await helpers.async_bulk(
                self._client, actions, refresh=False, pipeline=self.pipeline, raise_on_error=False
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка bulk-записи в Elasticsearch", extra={"reason": str(exc)})
            if self.metrics is not None:
                self.metrics.sink_sent.inc({"sink": self.name, "status": "error"}, value=count)
            self._buffer.clear()
            return False
        self._buffer.clear()
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"}, value=int(success))
            if errors:
                self.metrics.sink_sent.inc({"sink": self.name, "status": "error"}, value=len(errors))
        logger.info("Обогащённые события записаны", extra={"index": self._index_name(), "count": int(success)})
        return not errors

    async def stop(self) -> None:
        await self.flush()
        if self._client is not None:
            await self._client.close()
            self._client = None
        self._started = False

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"index": self.index, "batch_size": self.batch_size})
        return info

"""Коннектор к Wazuh Indexer."""

from __future__ import annotations

from typing import Any, AsyncIterator, Mapping

from siem_enricher.connectors.base import register_source
from siem_enricher.connectors.elasticsearch import ElasticsearchSource
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.event import NormalizedEvent

logger = get_logger("connectors.wazuh")


@register_source("wazuh_indexer")
class WazuhIndexerSource(ElasticsearchSource):
    """Источник алертов Wazuh из Wazuh Indexer (OpenSearch)."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        normalizer: Any = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        merged: dict[str, Any] = {
            "index": "wazuh-alerts-*",
            "timestamp_field": "@timestamp",
            "from_now": True,
            "batch_size": 500,
            "poll_interval_ms": 2000,
        }
        merged.update(dict(options or {}))
        super().__init__(merged, normalizer=normalizer, metrics=metrics, name=name or "wazuh_indexer")
        self.min_rule_level = int(self._option("min_rule_level", 0) or 0)
        self.agent_name = self._option("agent_name")
        self.load_full_log = bool(self._option("load_full_log", True))
        self.extra_query = self._build_wazuh_query()

    def _build_wazuh_query(self) -> dict[str, Any]:
        """Построить фильтр Wazuh-алертов."""
        must: list[dict[str, Any]] = []
        if self.min_rule_level > 0:
            must.append({"range": {"rule.level": {"gte": self.min_rule_level}}})
        if self.agent_name:
            must.append({"term": {"agent.name": str(self.agent_name)}})
        user_query = self._option("query")
        if isinstance(user_query, Mapping) and user_query:
            must.append(dict(user_query))
        return {"bool": {"must": must}} if must else {"match_all": {}}

    async def stream(self) -> AsyncIterator[NormalizedEvent]:
        logger.info(
            "Запуск обогащения алертов Wazuh",
            extra={
                "index": self.index,
                "min_rule_level": self.min_rule_level,
                "agent_name": self.agent_name,
                "load_full_log": self.load_full_log,
            },
        )
        async for event in super().stream():
            yield event

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"min_rule_level": self.min_rule_level, "agent_name": self.agent_name})
        return info

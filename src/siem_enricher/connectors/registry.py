"""Реестр коннекторов и вспомогательные функции сборки."""

from __future__ import annotations

from siem_enricher.connectors.base import (
    SINK_TYPES,
    SOURCE_TYPES,
    Connector,
    MultiSink,
    SinkConnector,
    SourceConnector,
    available_sinks,
    available_sources,
    build_sink,
    build_source,
    register_sink,
    register_source,
)


def describe_connector_types() -> dict[str, list[str]]:
    """Перечень доступных типов коннекторов (для CLI и ``/v1/version``)."""
    return {"sources": available_sources(), "sinks": available_sinks()}


def connector_names() -> dict[str, list[str]]:
    return {"sources": sorted(SOURCE_TYPES), "sinks": sorted(SINK_TYPES)}


__all__ = [
    "Connector",
    "MultiSink",
    "SINK_TYPES",
    "SOURCE_TYPES",
    "SinkConnector",
    "SourceConnector",
    "available_sinks",
    "available_sources",
    "build_sink",
    "build_source",
    "connector_names",
    "describe_connector_types",
    "register_sink",
    "register_source",
]

"""Коннекторы к SIEM: источники событий и приёмники обогащённых событий."""

from siem_enricher.connectors.base import (
    Connector,
    MultiSink,
    SinkConnector,
    SourceConnector,
    build_sink,
    build_source,
    register_sink,
    register_source,
)
from siem_enricher.connectors.checkpoint import CheckpointStore

# Регистрация типов коннекторов (порядок импорта важен)
from siem_enricher.connectors import file_replay as _file_replay  # noqa: F401
from siem_enricher.connectors import webhook as _webhook  # noqa: F401
from siem_enricher.connectors import elasticsearch as _elasticsearch  # noqa: F401
from siem_enricher.connectors import kafka as _kafka  # noqa: F401
from siem_enricher.connectors import wazuh as _wazuh  # noqa: F401
from siem_enricher.connectors.registry import (
    available_sinks,
    available_sources,
    connector_names,
    describe_connector_types,
)

__all__ = [
    "CheckpointStore",
    "Connector",
    "MultiSink",
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

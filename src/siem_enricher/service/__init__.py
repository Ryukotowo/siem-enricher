"""Сервисный слой: HTTP-API и среда выполнения конвейера."""

from __future__ import annotations

from typing import Any

from siem_enricher.service.runtime import EnrichmentRuntime, build_runtime, source_config

__all__ = [
    "EnrichmentRuntime",
    "build_runtime",
    "create_app",
    "serve",
    "source_config",
]


def __getattr__(name: str) -> Any:
    """Ленивый импорт HTTP-слоя (требует установленного FastAPI)."""
    if name == "create_app":
        from siem_enricher.service.app import create_app

        return create_app
    if name == "serve":
        from siem_enricher.service.app import serve

        return serve
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

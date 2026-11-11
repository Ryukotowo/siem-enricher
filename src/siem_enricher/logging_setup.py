"""Настройка логирования: структурированные JSON-логи и читаемый формат для консоли."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_event_id: ContextVar[str | None] = ContextVar("siem_enricher_event_id", default=None)

_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
    "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName", "process", "taskName",
    "message", "asctime",
}


@contextmanager
def event_context(event_id: str | None) -> Iterator[None]:
    """Привязать идентификатор события ко всем логам внутри блока."""
    token = _event_id.set(event_id)
    try:
        yield
    finally:
        _event_id.reset(token)


def current_event_id() -> str | None:
    return _event_id.get()


class JsonFormatter(logging.Formatter):
    """Формат JSON Lines: удобен для сбора логов самим SIEM."""

    def __init__(self, service: str = "siem-enricher", instance: str = "local") -> None:
        super().__init__()
        self.service = service
        self.instance = instance

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "instance": self.instance,
        }
        event_id = _event_id.get()
        if event_id:
            payload["event_id"] = event_id
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload.setdefault(key, _safe(value))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    """Читаемый формат для локальной отладки."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        base = f"{ts} {record.levelname:<7} [{record.name}] {record.getMessage()}"
        event_id = _event_id.get()
        if event_id:
            base += f" event_id={event_id}"
        extras = [
            f"{k}={_safe(v)}"
            for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_") and k not in {"event_id"}
        ]
        if extras:
            base += " " + " ".join(extras)
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value[:32]]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in list(value.items())[:32]}
    return str(value)


def setup_logging(
    level: str | int = "INFO",
    fmt: str = "json",
    service: str = "siem-enricher",
    instance: str = "local",
    stream: Any = None,
) -> logging.Logger:
    """Настроить корневой логгер сервиса. Возвращает логгер ``siem_enricher``."""
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(
        JsonFormatter(service, instance) if fmt.lower() == "json" else HumanFormatter()
    )

    root = logging.getLogger("siem_enricher")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False

    # Приглушаем избыточные логи сторонних библиотек
    for noisy in ("elastic_transport", "elasticsearch", "aiokafka", "urllib3", "httpx", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))

    return root


def get_logger(name: str | None = None) -> logging.Logger:
    """Логгер с префиксом пакета."""
    return logging.getLogger(f"siem_enricher.{name}" if name else "siem_enricher")

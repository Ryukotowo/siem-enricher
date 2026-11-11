"""Аудит решений: журнал срабатываний политик и выполненных действий."""

from __future__ import annotations

import atexit
import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FLUSH_EVERY = 32

_BUFFERS: dict[Path, list[str]] = {}
_LOCK = threading.Lock()


def _flush_path(path: Path) -> None:
    """Сбросить накопленные строки на диск (вызывается под замком)."""
    lines = _BUFFERS.get(path)
    if not lines:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write("".join(lines))
    _BUFFERS[path] = []


def _flush_all() -> None:
    with _LOCK:
        for path in list(_BUFFERS):
            try:
                _flush_path(path)
            except OSError:  # журнал недоступен — не мешаем завершению процесса
                pass


atexit.register(_flush_all)


class AuditLogger:
    """Потокобезопасный журнал аудита решений о применении политик."""

    def __init__(self, path: str | Path | None, enabled: bool = True,
                 flush_every: int = FLUSH_EVERY) -> None:
        self.path = Path(path) if path else None
        self.enabled = enabled and self.path is not None
        self._records_written = 0
        self._flush_every = max(1, flush_every)
        if self.enabled and self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Mapping[str, Any]) -> None:
        if not self.enabled or self.path is None:
            self._records_written += 1  # учёт «сухих» решений для отчётности
            return
        payload = dict(record)
        payload.setdefault("audit_ts", datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"))
        line = json.dumps(payload, ensure_ascii=False, default=str) + "\n"
        with _LOCK:
            buffer = _BUFFERS.setdefault(self.path, [])
            buffer.append(line)
            self._records_written += 1
            if len(buffer) >= self._flush_every:
                _flush_path(self.path)

    def flush(self) -> None:
        """Сбросить буфер этого журнала на диск."""
        if self.path is None:
            return
        with _LOCK:
            _flush_path(self.path)

    def close(self) -> None:
        """Синоним flush: дескриптор не удерживается между записями."""
        self.flush()

    @property
    def records_written(self) -> int:
        return self._records_written

    def read_all(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Прочитать журнал (используется сервисом и тестами)."""
        self.flush()
        if self.path is None or not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
                if limit is not None and len(records) >= limit:
                    break
        return records

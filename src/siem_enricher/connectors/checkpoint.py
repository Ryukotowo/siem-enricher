"""Сохранение позиции чтения источника (checkpoint)."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from siem_enricher.logging_setup import get_logger

logger = get_logger("connectors.checkpoint")


class CheckpointStore:
    """Простое файловое хранилище позиций чтения."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self.path is None or not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8")) or {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Не удалось прочитать checkpoint, начинаю с нуля",
                           extra={"path": str(self.path), "reason": str(exc)})
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def save(self) -> None:
        """Атомарно записать состояние на диск."""
        if self.path is None:
            return
        with self._lock:
            snapshot = dict(self._data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def update(self, key: str, value: Any) -> None:
        """Обновить значение и сразу сохранить."""
        self.set(key, value)
        self.save()

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)

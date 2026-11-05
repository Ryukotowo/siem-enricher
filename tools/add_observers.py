"""Уведомления конвейера: панель обновляется и в режиме потока."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "src" / "siem_enricher" / "enricher" / "pipeline.py"
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"

INIT_OLD = "        self.store = store or builder.store"
INIT_NEW = """        self.store = store or builder.store
        self.observers: list[Callable[[dict[str, Any]], None]] = []"""

METHODS = '''    def add_observer(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Подписать наблюдателя на обогащённые документы (панель аналитика, отладка)."""
        self.observers.append(callback)

    def _notify_observers(self, document: dict[str, Any]) -> None:
        for callback in self.observers:
            try:
                callback(document)
            except Exception as exc:  # noqa: BLE001 - наблюдатель не должен ломать обработку
                logger.warning("Наблюдатель конвейера завершился ошибкой",
                               extra={"reason": str(exc)})

    @classmethod
    def from_config('''

RETURN_OLD = """            return enriched

    def enrich_document("""
RETURN_NEW = """            self._notify_observers(document)
            return enriched

    def enrich_document("""

APP_OLD = """    panel_buffer = EventBuffer(500)
    if register_panel(app, panel_buffer):
        logger.info("Панель аналитика доступна по адресу /ui")"""
APP_NEW = """    panel_buffer = EventBuffer(500)
    if register_panel(app, panel_buffer):
        pipeline.add_observer(panel_buffer.add)
        logger.info("Панель аналитика доступна по адресу /ui (обновляется по мере потока)")"""


def patch(path: Path, pairs: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if new.strip() and new.strip() in text:
            print(f"  уже есть: {old[:46]}")
            continue
        if old not in text:
            print(f"  !! не найдено в {path.name}: {old[:46]}")
            continue
        text = text.replace(old, new, 1)
        print(f"  патч {path.name}: {old[:46]}")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    print("конвейер:")
    patch(PIPELINE, [(INIT_OLD, INIT_NEW), ("    @classmethod\n    def from_config(", METHODS),
                     (RETURN_OLD, RETURN_NEW)])

    text = PIPELINE.read_text(encoding="utf-8")
    if "Callable" not in text.split("class ")[0]:
        match = re.search(r"from typing import ([^\n]+)", text)
        if match and "Callable" not in match.group(1):
            imports = match.group(1)
            text = text.replace(f"from typing import {imports}",
                                f"from typing import Callable, {imports}", 1)
            PIPELINE.write_text(text, encoding="utf-8")
            print("  добавлен Callable в импорты")

    print("сервис:")
    patch(APP, [(APP_OLD, APP_NEW)])

    for path in (PIPELINE, APP):
        ast.parse(path.read_text(encoding="utf-8"))
        print(f"  синтаксис ок: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

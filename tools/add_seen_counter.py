"""Счётчик «всего обработано» отдельно от содержимого буфера."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

INIT_OLD = '''    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)
        self._subscribers: list[Any] = []'''
INIT_NEW = '''    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)
        self._subscribers: list[Any] = []
        self._seen = 0
        self._replaced = 0'''

ADD_OLD = '''    def add(self, document: dict[str, Any]) -> None:
        record = compact(document)
        if record.get("event_id"):
            self._items = deque((i for i in self._items if i.get("event_id") != record["event_id"]),
                                maxlen=self._items.maxlen)
        self._items.append(record)'''
ADD_NEW = '''    def add(self, document: dict[str, Any]) -> None:
        record = compact(document)
        self._seen += 1
        if record.get("event_id"):
            kept = [i for i in self._items if i.get("event_id") != record["event_id"]]
            if len(kept) != len(self._items):
                self._replaced += 1
            self._items = deque(kept, maxlen=self._items.maxlen)
        self._items.append(record)'''

STATS_OLD = '''    def stats(self) -> dict[str, Any]:
        items = list(self._items)
        return {
            "total": len(items),
            "critical": sum(1 for item in items if item.get("severity") == "critical"),
            "blocked": sum(1 for item in items if item.get("decision") == "block"),
        }'''
STATS_NEW = '''    def stats(self) -> dict[str, Any]:
        items = list(self._items)
        return {
            "total": len(items),
            "seen": self._seen,
            "replaced": self._replaced,
            "capacity": self._items.maxlen,
            "critical": sum(1 for item in items if item.get("severity") == "critical"),
            "blocked": sum(1 for item in items if item.get("decision") == "block"),
        }'''

MARKUP_OLD = '''      <div><b id="c-total">0</b>событий</div>'''
MARKUP_NEW = '''      <div><b id="c-total">0</b>обработано всего</div>
      <div><b id="c-buf">0</b>в буфере</div>'''

JS_OLD = '''    document.getElementById('c-total').textContent = DATA.length;'''
JS_NEW = '''    document.getElementById('c-total').textContent = (STATS.seen !== undefined ? STATS.seen : DATA.length);
    document.getElementById('c-buf').textContent = DATA.length + ' из ' + (STATS.capacity || 500);'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (INIT_OLD, INIT_NEW, "буфер: счётчики"),
        (ADD_OLD, ADD_NEW, "буфер: подсчёт обработанных"),
        (STATS_OLD, STATS_NEW, "буфер: новые поля статистики"),
        (MARKUP_OLD, MARKUP_NEW, "шапка: два показателя"),
        (JS_OLD, JS_NEW, "шапка: обновление счётчиков"),
    ):
        if new in text:
            continue
        if old not in text:
            print(f"  предупреждение: не найдено — {label}")
            continue
        text = text.replace(old, new, 1)
        changed += 1
        print(f"  {label}")

    # STATS должен быть доступен в функции отрисовки
    if "const STATS" not in text and "STATS =" not in text:
        marker = "  const DATA = payload.events;"
        if marker in text:
            text = text.replace(marker, "  const DATA = payload.events;\n  const STATS = payload.stats || {};", 1)
            changed += 1
            print("  отрисовка: статистика из ответа")
        else:
            print("  предупреждение: не найден разбор ответа")

    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

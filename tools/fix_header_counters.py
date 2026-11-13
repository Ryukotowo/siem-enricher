"""Точная правка шапки панели: два счётчика."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

MARKUP_OLD = '    <div><b id="c-total">0</b>событий</div>'
MARKUP_NEW = ('    <div><b id="c-total">0</b>обработано всего</div>\n'
              '    <div><b id="c-buf">0</b>в буфере</div>')

JS_OLD = "  document.getElementById('c-total').textContent = DATA.length;"
JS_NEW = ("  document.getElementById('c-total').textContent =\n"
          "    (STATS.seen !== undefined ? STATS.seen : DATA.length);\n"
          "  const bufCell = document.getElementById('c-buf');\n"
          "  if (bufCell) bufCell.textContent = DATA.length + ' из ' + (STATS.capacity || 500);")

STATS_MARK = "  const rows = visibleRows();"
STATS_NEW = ("  const STATS = window.__stats || {};\n"
             "  const rows = visibleRows();")


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if 'id="c-buf"' not in text:
        if MARKUP_OLD not in text:
            print("!! не найдена разметка счётчика")
            return 1
        text = text.replace(MARKUP_OLD, MARKUP_NEW, 1)
        changed += 1
        print("  разметка: обработано всего + в буфере")
    if "STATS.seen" not in text:
        if JS_OLD not in text:
            print("!! не найдено обновление счётчика")
            return 1
        text = text.replace(JS_OLD, JS_NEW, 1)
        changed += 1
        print("  обновление счётчиков")
    if "window.__stats" not in text:
        if STATS_MARK in text:
            text = text.replace(STATS_MARK, STATS_NEW, 1)
            changed += 1
            print("  статистика из ответа сервера")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

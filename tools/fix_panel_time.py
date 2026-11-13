"""Панель: убрать счётчик буфера и показывать местное время события."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

MARKUP_OLD = '''    <div><b id="c-buf">0</b>в буфере</div>
'''
JS_OLD = '''  const bufCell = document.getElementById('c-buf');
  if (bufCell) bufCell.textContent = DATA.length + ' из ' + (STATS.capacity || 500);
'''

TIME_OLD = '''<td class="num">${(e.ts || '').slice(11, 19)}</td>'''
TIME_NEW = '''<td class="num" title="${e.ts || ''}">${fmtTime(e.ts)}</td>'''

HELPER_ANCHOR = "function render() {"
HELPER = '''function fmtTime(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return (ts || '').slice(11, 19);
  return date.toLocaleTimeString('ru-RU', {hour12: false});
}

function render() {'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (MARKUP_OLD, "", "удалён счётчик «в буфере»"),
        (JS_OLD, "", "удалён JS счётчика буфера"),
        (TIME_OLD, TIME_NEW, "время показывается по местному поясу"),
        (HELPER_ANCHOR, HELPER, "добавлен fmtTime()"),
    ):
        if label.startswith("удалён") and old not in text:
            continue
        if new and new in text:
            continue
        if old not in text:
            print(f"  предупреждение: не найдено — {label}")
            continue
        text = text.replace(old, new, 1)
        changed += 1
        print(f"  {label}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

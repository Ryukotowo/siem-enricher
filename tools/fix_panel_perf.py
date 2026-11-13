"""Быстрый рендер: счётчики на клиенте, ограничение строк, отложенная отрисовка."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

COUNTER_OLD = '''  const STATS = window.__stats || {};
  document.getElementById('c-total').textContent =
    (STATS.seen !== undefined ? STATS.seen : DATA.length);'''
COUNTER_NEW = '''  const STATS = window.__stats || {};
  document.getElementById('c-total').textContent =
    Math.max(SEEN || 0, STATS.seen || 0, DATA.length);'''

BODY_OLD = '''  const body = document.getElementById('rows');'''
BODY_NEW = '''  const body = document.getElementById('rows');
  const shown = rows.slice(0, MAX_ROWS);'''

COUNTER_LINE = '''  if (counter) counter.textContent = `показано ${rows.length} из ${DATA.length}`;'''
COUNTER_LINE_NEW = '''  if (counter) counter.textContent = `показано ${shown.length} из ${DATA.length}`;'''

STATE_MARK = "let DATA = [], SELECTED = null;"
STATE_NEW = '''let DATA = [], SELECTED = null;
let SEEN = 0, MAX_ROWS = 200, MODAL_OPEN = false, RENDER_QUEUED = false;

function scheduleRender() {
  if (RENDER_QUEUED) return;
  RENDER_QUEUED = true;
  const run = () => { RENDER_QUEUED = false; render(); };
  if (window.requestAnimationFrame) requestAnimationFrame(run); else setTimeout(run, 120);
}'''

SSE_OLD = '''  DATA = [record, ...DATA.filter(item => item.event_id !== record.event_id)].slice(0, 500);
  if (!SELECTED && record.decision === 'block') select(record.event_id);
  render();'''
SSE_NEW = '''  DATA = [record, ...DATA.filter(item => item.event_id !== record.event_id)].slice(0, 500);
  SEEN += 1;
  if (!SELECTED && record.decision === 'block') select(record.event_id);
  if (!MODAL_OPEN) scheduleRender();'''

SETTINGS_OLD = '''async function openSettings() {
  SETTINGS_RESULT.textContent = '';'''
SETTINGS_NEW = '''async function openSettings() {
  MODAL_OPEN = true;
  SETTINGS_RESULT.textContent = '';'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (STATE_MARK, STATE_NEW, "клиентские счётчики и отложенный рендер"),
        (COUNTER_OLD, COUNTER_NEW, "счётчик «обработано» растёт сразу"),
        (BODY_OLD, BODY_NEW, "ограничение строк таблицы"),
        (COUNTER_LINE, COUNTER_LINE_NEW, "подпись «показано»"),
        (SSE_OLD, SSE_NEW, "поток обновляет счётчики без перезагрузки"),
        (SETTINGS_OLD, SETTINGS_NEW, "настройки останавливают тяжёлый рендер"),
    ):
        if new in text:
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

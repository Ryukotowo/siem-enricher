"""Перенести STATS из exportCsv в render."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

REMOVE_OLD = '''function exportCsv() {
  const STATS = window.__stats || {};
  const rows = visibleRows();'''
REMOVE_NEW = '''function exportCsv() {
  const rows = visibleRows();'''

ADD_OLD = '''  const STATS = window.__stats || {};
  const rows = visibleRows();
  renderDashboard();'''
ADD_NEW = '''  const STATS = window.__stats || {};
  const rows = visibleRows();
  renderDashboard();'''

TOTAL_OLD = "  document.getElementById('c-total').textContent =\n    (STATS.seen !== undefined ? STATS.seen : DATA.length);"
TOTAL_NEW = ("  const STATS = window.__stats || {};\n"
             "  document.getElementById('c-total').textContent =\n"
             "    (STATS.seen !== undefined ? STATS.seen : DATA.length);")


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if REMOVE_OLD in text:
        text = text.replace(REMOVE_OLD, REMOVE_NEW, 1)
        changed += 1
        print("  убрано объявление из exportCsv")
    if "const STATS = window.__stats || {};\n  document.getElementById('c-total')" not in text:
        if TOTAL_OLD not in text:
            print("!! не найдено обновление c-total")
            return 1
        text = text.replace(TOTAL_OLD, TOTAL_NEW, 1)
        changed += 1
        print("  STATS объявлен в render()")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

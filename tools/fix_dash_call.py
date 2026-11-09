"""Перенос вызова дашборда в render() и удаление дубля проверки."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

DUP = "  try {\n  if (!spark) return;\n"
DUP_FIX = "  try {\n"

CALL_BAD = "  const rows = visibleRows();\n  renderDashboard();\n"
CALL_GOOD = "  const rows = visibleRows();\n"

RENDER_ANCHOR = "function render() {\n  refreshActions();\n  const rows = visibleRows();"
RENDER_NEW = "function render() {\n  refreshActions();\n  const rows = visibleRows();\n  renderDashboard();"


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if DUP in text:
        text = text.replace(DUP, DUP_FIX, 1)
        changed += 1
        print("удалён дубль проверки spark")
    if CALL_BAD in text:
        text = text.replace(CALL_BAD, CALL_GOOD, 1)
        changed += 1
        print("удалён вызов из visibleRows")
    if RENDER_NEW not in text and RENDER_ANCHOR in text:
        text = text.replace(RENDER_ANCHOR, RENDER_NEW, 1)
        changed += 1
        print("вызов добавлен в render()")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

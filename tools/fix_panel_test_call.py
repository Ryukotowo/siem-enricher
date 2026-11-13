"""Использовать compact вместо несуществующего panel_module."""

from __future__ import annotations

import ast
from pathlib import Path

TEST = Path(__file__).resolve().parents[1] / "tests" / "unit" / "test_panel.py"

OLD = '        record = panel_module.event_to_panel(document)'
NEW = '        record = compact(document)'


def main() -> int:
    text = TEST.read_text(encoding="utf-8")
    if "panel_module" not in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найден вызов")
        return 1
    text = text.replace(OLD, NEW, 1)
    TEST.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("тест использует compact()")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Исправление CSV-экспорта: BOM и перевод строки без спецсимволов."""

from __future__ import annotations

import ast
import re
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

PATTERN = re.compile(
    r"const blob = new Blob\(\[.*?\], \{type: 'text/csv;charset=utf-8'\}\);",
    re.DOTALL,
)
REPLACEMENT = (
    "const blob = new Blob([String.fromCharCode(0xFEFF) + lines.join(String.fromCharCode(10))], "
    "{type: 'text/csv;charset=utf-8'});"
)


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "String.fromCharCode(0xFEFF)" in text:
        print("уже исправлено")
        return 0
    if not PATTERN.search(text):
        print("!! не найден блок экспорта")
        return 1
    text = PATTERN.sub(REPLACEMENT, text, count=1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("экспорт исправлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

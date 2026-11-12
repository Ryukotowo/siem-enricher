"""Путь настроек: передавать приложение в persist/restore."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

PAIRS = [
    ("def persist_settings(values: dict[str, Any], rules: dict[str, Any] | None = None) -> None:",
     "def persist_settings(values: dict[str, Any], rules: dict[str, Any] | None = None,\n"
     "                     app: Any = None) -> None:"),
    ("def restore_settings() -> dict[str, Any]:",
     "def restore_settings(app: Any = None) -> dict[str, Any]:"),
]


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print(f"  {old.split('(')[0].replace('def ', '')}: параметр app")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

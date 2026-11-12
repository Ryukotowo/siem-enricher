"""Передача приложения в persist_settings и restore_settings."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

PAIRS = [
    ('persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)})',
     'persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)}, app=app)'),
    ("def restore_settings(app: Any) -> list[str]:",
     "def restore_settings(app: Any = None) -> list[str]:"),
]


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

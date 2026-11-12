"""Юникод в именах организаций: кириллица не должна схлопываться в default."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", raw).strip("-.")'
NEW = '    cleaned = re.sub(r"[^\\w.-]+", "-", raw, flags=re.UNICODE).strip("-.")'


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найдена строка нормализации")
        return 1
    text = text.replace(OLD, NEW, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("current_tenant: кириллица сохраняется")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

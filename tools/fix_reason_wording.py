"""Понятнее объяснение класса по умолчанию."""

from __future__ import annotations

import ast
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "fallback_rules.py"

OLD = 'reason="правила не сработали, применён класс по умолчанию",'
NEW = 'reason="ни одно правило не дало признаков, класс взят по умолчанию",'


def main() -> int:
    text = RULES.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найдена строка причины")
        return 1
    RULES.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("формулировка причины уточнена")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

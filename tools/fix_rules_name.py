"""KeywordRule использует name, а не id — правим модуль правил."""

from __future__ import annotations

import ast
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "rules_config.py"

PAIRS = [
    ("    by_id = {rule.id: rule for rule in base}\n    order = [rule.id for rule in base]",
     "    by_id = {rule.name: rule for rule in base}\n    order = [rule.name for rule in base]"),
    ("    return tuple(by_id[rule_id] for rule_id in order if rule_id in by_id)",
     "    return tuple(by_id[rule_id] for rule_id in order if rule_id in by_id)"),
]


def main() -> int:
    text = RULES.read_text(encoding="utf-8")
    old, new = PAIRS[0]
    if "rule.name" in text:
        print("уже исправлено")
        return 0
    if old not in text:
        print("!! не найден блок _merge")
        return 1
    text = text.replace(old, new, 1)
    RULES.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("правила используют имя правила как идентификатор")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

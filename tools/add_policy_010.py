"""Добавление правила POL-010 (блокировка шифрования защищаемых данных)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "config" / "policies.json"

RULE = {
    "id": "POL-010",
    "title": "Шифрование защищаемых данных (ransomware)",
    "description": (
        "Действие шифрования над файлом класса не ниже служебного. Массовое изменение данных "
        "шифровальщиком приводит к недоступности информации, поэтому реакция — блокировка."
    ),
    "enabled": True,
    "priority": 120,
    "severity": "critical",
    "tags": ["ransomware", "integrity"],
    "when": {
        "all": [
            {"field": "data_sensitivity", "op": "gte", "value": "internal"},
            {"field": "action", "op": "in", "value": ["encrypt"]},
        ]
    },
    "then": [
        {
            "type": "alert",
            "channel": "siem",
            "severity": "critical",
            "message": "Шифрование защищаемых данных (признак шифровальщика)",
        },
        {
            "type": "block",
            "target": "process",
            "mode": "dry_run",
            "reason": "POL-010: шифрование защищаемых данных",
        },
        {"type": "tag", "value": "dlp:ransomware"},
    ],
}


def main() -> int:
    data = json.loads(POLICIES.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if any(rule.get("id") == RULE["id"] for rule in rules):
        print("правило POL-010 уже есть")
        return 0
    rules.append(RULE)
    data["rules"] = rules
    data.setdefault("metadata", {})["updated"] = "2026-10-19"
    data["metadata"]["description"] = (
        "Набор правил применения политик к обогащённым событиям "
        "(10 правил: отправка, секреты, массовый доступ, упаковка, кадровые данные, "
        "шифрование, сокрытие, архив наружу, открытое размещение, шифрование данных)"
    )
    POLICIES.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"правило POL-010 добавлено, всего правил: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

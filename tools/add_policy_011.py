"""Добавление правила POL-011 (копирование защищаемых данных на съёмный носитель)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "config" / "policies.json"

RULE = {
    "id": "POL-011",
    "title": "Копирование защищаемых данных на съёмный носитель",
    "description": (
        "В событии есть объект на съёмном носителе (том E:…Z:, каталог /media, /mnt) и класс "
        "данных не ниже конфиденциального. Типовой канал выноса информации без сети."
    ),
    "enabled": True,
    "priority": 110,
    "severity": "critical",
    "tags": ["removable-media", "data-leak"],
    "when": {
        "all": [
            {"field": "removable_destinations_count", "op": "gte", "value": 1},
            {"field": "data_sensitivity", "op": "gte", "value": "confidential"},
            {"field": "action", "op": "in", "value": ["copy", "move", "write", "archive"]},
        ]
    },
    "then": [
        {
            "type": "alert",
            "channel": "siem",
            "severity": "critical",
            "message": "Копирование защищаемых данных на съёмный носитель",
        },
        {
            "type": "block",
            "target": "process",
            "mode": "dry_run",
            "reason": "POL-011: вынос данных на съёмном носителе",
        },
        {"type": "tag", "value": "dlp:removable-media"},
    ],
}


def main() -> int:
    data = json.loads(POLICIES.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if any(rule.get("id") == RULE["id"] for rule in rules):
        print("правило POL-011 уже есть")
        return 0
    rules.append(RULE)
    data["rules"] = rules
    data.setdefault("metadata", {})["updated"] = "2026-10-19"
    POLICIES.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"правило POL-011 добавлено, всего правил: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

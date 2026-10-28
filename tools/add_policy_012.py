"""Добавление правила POL-012 (блокировка массового копирования защищаемых данных)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "config" / "policies.json"

RULE = {
    "id": "POL-012",
    "title": "Массовое копирование защищаемых данных",
    "description": (
        "Восемь и более файлов в одном событии с классом не ниже конфиденциального при "
        "действии копирования, перемещения или архивирования. Признак выгрузки каталога "
        "или подготовки крупной утечки."
    ),
    "enabled": True,
    "priority": 105,
    "severity": "critical",
    "tags": ["mass-copy", "data-leak"],
    "when": {
        "all": [
            {"field": "data_sensitivity", "op": "gte", "value": "confidential"},
            {"field": "files_count", "op": "gte", "value": 8},
            {"field": "action", "op": "in", "value": ["copy", "move", "archive", "read"]},
        ]
    },
    "then": [
        {
            "type": "alert",
            "channel": "siem",
            "severity": "critical",
            "message": "Массовое копирование защищаемых данных",
        },
        {
            "type": "block",
            "target": "process",
            "mode": "dry_run",
            "reason": "POL-012: массовое копирование защищаемых данных",
        },
        {"type": "tag", "value": "dlp:mass-copy"},
    ],
}


def main() -> int:
    data = json.loads(POLICIES.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if any(rule.get("id") == RULE["id"] for rule in rules):
        print("правило POL-012 уже есть")
        return 0
    rules.append(RULE)
    data["rules"] = rules
    data.setdefault("metadata", {})["updated"] = "2026-10-19"
    POLICIES.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"правило POL-012 добавлено, всего правил: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

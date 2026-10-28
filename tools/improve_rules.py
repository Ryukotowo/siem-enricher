"""Уточнение правил по результатам разбора остаточных ошибок."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "config" / "policies.json"

NEW_008_WHEN = {
    "all": [
        {"field": "data_sensitivity", "op": "gte", "value": "internal"},
        {"field": "action", "op": "in",
         "value": ["upload", "send", "copy", "move", "archive", "encrypt"]},
        {"field": "provenance_depth", "op": "gte", "value": 4},
        {"field": "external_destinations_count", "op": "gte", "value": 1},
        {"field": "risk_score", "op": "gte", "value": 0.4},
    ]
}

NEW_013 = {
    "id": "POL-013",
    "title": "Архивирование защищаемых данных",
    "description": (
        "Упаковка файлов класса не ниже конфиденциального без внешнего адресата и без "
        "съёмного носителя. Архив — типовой первый шаг подготовки выноса информации."
    ),
    "enabled": True,
    "priority": 100,
    "severity": "high",
    "tags": ["staging", "archive"],
    "when": {
        "all": [
            {"field": "data_sensitivity", "op": "gte", "value": "confidential"},
            {"field": "action", "op": "in", "value": ["archive"]},
        ]
    },
    "then": [
        {
            "type": "alert",
            "channel": "siem",
            "severity": "high",
            "message": "Архивирование защищаемых данных",
        },
        {
            "type": "block",
            "target": "process",
            "mode": "dry_run",
            "reason": "POL-013: архивирование защищаемых данных",
        },
        {"type": "tag", "value": "dlp:staging-archive"},
    ],
}


def main() -> int:
    data = json.loads(POLICIES.read_text(encoding="utf-8"))
    rules = data.get("rules", [])

    updated = False
    for rule in rules:
        if rule.get("id") == "POL-008":
            if rule.get("when") == NEW_008_WHEN:
                print("POL-008 уже уточнён")
            else:
                rule["when"] = NEW_008_WHEN
                rule["description"] = (
                    "Длинная цепочка происхождения с внешним узлом у защищаемых данных при "
                    "действии, перемещающем данные. Требует класса не ниже служебного: длинная "
                    "история открытого файла сама по себе не является нарушением."
                )
                updated = True
                print("POL-008 уточнён: учитываются класс данных и действие")

    if any(rule.get("id") == "POL-013" for rule in rules):
        print("POL-013 уже есть")
    else:
        rules.append(NEW_013)
        updated = True
        print("POL-013 добавлен: блокировка архивирования защищаемых данных")

    if updated:
        data["rules"] = rules
        data.setdefault("metadata", {})["updated"] = "2026-10-19"
        POLICIES.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"правил в конфигурации: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

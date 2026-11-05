"""Конфиг для демонстрации Kafka: источник и приёмник заменены, остальное как в рабочем."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "config" / "config.local.json"
TARGET = ROOT / "config" / "config.kafka.json"

SOURCE = {
    "type": "kafka",
    "options": {
        "bootstrap_servers": "localhost:9092",
        "topics": ["siem-events"],
        "group_id": "siem-enricher-demo",
        "auto_offset_reset": "earliest",
        "poll_timeout_ms": 1000,
    },
}

SINK = {
    "type": "multi",
    "options": {
        "sinks": [
            {
                "type": "kafka",
                "options": {
                    "bootstrap_servers": "localhost:9092",
                    "topic": "siem-enriched",
                    "acks": "all",
                },
            },
            {
                "type": "file_jsonl",
                "options": {"path": "var/screens/kafka_enriched.jsonl", "mode": "append"},
            },
        ]
    },
}


def main() -> int:
    data = json.loads(BASE.read_text(encoding="utf-8"))
    data["source"] = SOURCE
    data["sink"] = SINK
    data.setdefault("service", {})["instance_id"] = "enricher-kafka-demo"
    TARGET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"создан {TARGET.name}: источник kafka, приёмники kafka + файл")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

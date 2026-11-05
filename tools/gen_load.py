"""Генерация набора для нагрузочного прогона: тиражирование с уникальными идентификаторами."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "var" / "experiment" / "dataset.jsonl"
TARGET = ROOT / "var" / "load" / "events_15k.jsonl"
COUNT = 15_000


def main() -> int:
    events = [json.loads(line) for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]
    TARGET.parent.mkdir(parents=True, exist_ok=True)

    with TARGET.open("w", encoding="utf-8") as handle:
        for index in range(COUNT):
            base = events[index % len(events)]
            event = json.loads(json.dumps(base, ensure_ascii=False))
            base_id = str(base.get("id") or base.get("event_id") or "0")
            prefix = base_id.split(".")[0]
            event["id"] = f"{prefix}.{index + 1:06d}"
            event["@timestamp"] = f"2026-10-19T{(index // 3600) % 24:02d}:{(index // 60) % 60:02d}:{index % 60:02d}Z"
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    size = TARGET.stat().st_size / 1024 / 1024
    print(f"сгенерировано {COUNT} событий: {TARGET} ({size:.1f} МБ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

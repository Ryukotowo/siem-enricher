"""Пункт 4: регрессионный набор фиксированных путей для проверки забывания."""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "var" / "datasets" / "names_1500_masked.jsonl"
TARGET = ROOT / "ml" / "regression_set.jsonl"
COUNT = 240
SEED = 2026


def main() -> int:
    if not SOURCE.exists():
        print(f"!! нет исходного набора {SOURCE}")
        return 1
    rows = [json.loads(line) for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_level: dict[str, list[dict]] = {}
    for row in rows:
        by_level.setdefault(row["level"], []).append(row)

    rng = random.Random(SEED)
    picked: list[dict] = []
    per_level = max(1, COUNT // len(by_level))
    for level, items in by_level.items():
        rng.shuffle(items)
        picked.extend(items[:per_level])

    result = [
        {"path": row["path"], "name": row["name"], "level": row["level"]}
        for row in picked
    ]
    TARGET.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in result) + "\n",
                      encoding="utf-8")
    counts = {level: sum(1 for row in result if row["level"] == level) for level in by_level}
    print(f"регрессионный набор: {len(result)} путей -> {TARGET.name}")
    print(f"по классам: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

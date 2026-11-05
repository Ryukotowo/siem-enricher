"""Экспорт набора без служебных пометок: для слепой проверки.

Убираются поле source и идентификаторы вида synth-0001; порядок перемешивается,
чтобы шаблонные группы не шли подряд. Соответствие исходным id сохраняется в ключ.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "var" / "datasets" / "synth_names_1500.jsonl"
TARGET = ROOT / "var" / "datasets" / "names_1500.jsonl"
KEY = ROOT / "var" / "datasets" / "names_1500.key.json"
SEED = 771


def main() -> int:
    rows = [json.loads(line) for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]
    random.Random(SEED).shuffle(rows)

    key: dict[str, str] = {}
    exported = []
    for index, row in enumerate(rows, start=1):
        new_id = f"{index:04d}"
        key[new_id] = str(row.get("id", ""))
        exported.append({
            "id": new_id,
            "path": row.get("path"),
            "name": row.get("name"),
            "directory": row.get("directory"),
            "category": row.get("category"),
            "level": row.get("level"),
        })

    TARGET.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in exported) + "\n",
                      encoding="utf-8")
    KEY.write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"экспортировано: {len(exported)} строк -> {TARGET.name}")
    print(f"ключ соответствия -> {KEY.name}")
    print("поля:", sorted(exported[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

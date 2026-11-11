"""Исправление битой строки с RUN_PIPELINE в compose."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"

BROKEN = "ENRICHER_MODE: serve\\`n      RUN_PIPELINE"
FIXED_OLD = 'ENRICHER_MODE: serve`n      RUN_PIPELINE: "1"'
FIXED_NEW = 'ENRICHER_MODE: serve\n      RUN_PIPELINE: "1"'


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    if FIXED_OLD in text:
        text = text.replace(FIXED_OLD, FIXED_NEW, 1)
        COMPOSE.write_text(text, encoding="utf-8")
        print("исправлено: литерал \\`n заменён на перевод строки")
    else:
        print("битая строка не найдена, проверяю результат")
    lines = text.splitlines()
    for index in range(68, min(78, len(lines))):
        print(f"{index + 1}: {lines[index]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

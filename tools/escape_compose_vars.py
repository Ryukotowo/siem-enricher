"""Экранировать переменные оболочки в команде producer-loop."""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

PAIRS = [
    ('--scenario "$SCENARIO"', '--scenario "$$SCENARIO"'),
    ('sleep "$INTERVAL";', 'sleep "$$INTERVAL";'),
]


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if new in text:
            continue
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
    if changed:
        COMPOSE.write_text(text, encoding="utf-8")
    print(f"экранировано переменных: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

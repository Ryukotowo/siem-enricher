"""Перенос опубликованных портов compose на свободные."""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

PAIRS = [
    ('- "8080:8080"', '- "8081:8080"'),
    ('- "3000:3000"', '- "3001:3000"'),
    ('- "9090:9090"', '- "9091:9090"'),
    ('- "7280:7280"', '- "7281:7280"'),
    ('- "9644:9644"', '- "9645:9644"'),
    ('- "9200:9200"', '- "9201:9200"'),
    ('- "9092:9092"', '- "19092:9092"'),
]


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print(f"  {old} -> {new}")
    COMPOSE.write_text(text, encoding="utf-8")
    print(f"перенесено портов: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

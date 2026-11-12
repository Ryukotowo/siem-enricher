"""Сервис trainer в compose: обучение отдельным профилем."""

from __future__ import annotations

import ast
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

SERVICE = '''  trainer:
    build:
      context: .
      dockerfile: Dockerfile.trainer
    image: siem-enricher-trainer:0.1.0
    container_name: siem-enricher-trainer
    profiles: ["trainer"]
    environment:
      TENANT: "${TENANT:-default}"
      INPUT: "${TRAIN_INPUT:-}"
    volumes:
      - ./ml:/app/ml
      - ./var:/app/var
      - ./config:/app/config
    networks:
      - enricher-net
'''

ANCHOR = "  quickwit:\n"


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    if "  trainer:" in text:
        print("сервис trainer уже есть")
        return 0
    if ANCHOR not in text:
        print("!! не найден якорь quickwit")
        return 1
    text = text.replace(ANCHOR, SERVICE + "\n" + ANCHOR, 1)
    COMPOSE.write_text(text, encoding="utf-8")
    print("compose: добавлен профиль trainer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

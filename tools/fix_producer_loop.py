"""producer-loop запускает скрипт, а не однострочную команду."""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

START = "  producer-loop:\n"
END = "  producer:\n"

NEW_SERVICE = '''  producer-loop:
    image: siem-enricher:0.2.0
    profiles: ["producer"]
    container_name: siem-enricher-producer-loop
    depends_on:
      redpanda:
        condition: service_healthy
      redpanda-init:
        condition: service_completed_successfully
    environment:
      INTERVAL: "${PRODUCER_INTERVAL:-5}"
      SCENARIO: "${PRODUCER_SCENARIO:-mixed}"
      COUNT: "${PRODUCER_COUNT:-10}"
    entrypoint: ["/bin/sh", "/app/deploy/demo/producer_loop.sh"]
    volumes:
      - ./var:/app/var
      - ./deploy/demo/producer_loop.sh:/app/deploy/demo/producer_loop.sh:ro
    networks: [enricher-net]
    restart: unless-stopped

'''


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    start = text.find(START)
    if start < 0:
        print("!! не найден producer-loop")
        return 1
    end = text.find(END, start + len(START))
    if end < 0:
        print("!! не найден конец блока")
        return 1
    text = text[:start] + NEW_SERVICE + text[end:]
    COMPOSE.write_text(text, encoding="utf-8")
    print("producer-loop переведён на скрипт")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

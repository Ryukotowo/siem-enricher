"""Сервис непрерывного потока в compose (профиль producer)."""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

SERVICE = '''  producer-loop:
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
    entrypoint: ["/bin/sh", "-lc"]
    command: >
      while true; do
        python /app/tools/generate_sample_events.py --scenario "$SCENARIO" --count 10
          --out /app/var/stream.jsonl &&
        python /app/tools/kafka_tool.py publish --bootstrap redpanda:9092
          --topic siem.raw.events --input /app/var/stream.jsonl;
        sleep "$INTERVAL";
      done
    volumes:
      - ./var:/app/var
    networks: [enricher-net]
    restart: unless-stopped

'''

ANCHOR = "  producer:\n"


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    if "producer-loop" in text:
        print("сервис producer-loop уже есть")
        return 0
    if ANCHOR not in text:
        print("!! не найден сервис producer")
        return 1
    COMPOSE.write_text(text.replace(ANCHOR, SERVICE + ANCHOR, 1), encoding="utf-8")
    print("compose: сервис producer-loop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

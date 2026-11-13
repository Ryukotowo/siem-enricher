#!/bin/sh
# Непрерывная публикация синтетических событий в Kafka для показа стенда.
#
# Переменные:
#   INTERVAL — пауза между порциями, секунды
#   SCENARIO — сценарий генератора (mixed, benign, ransomware, public)
#   COUNT    — сколько событий в порции
set -eu

INTERVAL="${INTERVAL:-5}"
SCENARIO="${SCENARIO:-mixed}"
COUNT="${COUNT:-10}"

while true; do
  python /app/tools/generate_sample_events.py --scenario "$SCENARIO" --count "$COUNT" \
    --out /app/var/stream.jsonl
  python /app/tools/kafka_tool.py publish --bootstrap redpanda:9092 \
    --topic siem.raw.events --input /app/var/stream.jsonl
  sleep "$INTERVAL"
done

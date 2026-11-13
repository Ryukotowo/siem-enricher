#!/usr/bin/env bash
# Быстрая диагностика после оптимизации приёмников.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "--- статус ---"
docker compose ps enricher --format '{{.Name}} {{.Status}}'

echo "--- последние строки лога ---"
docker logs siem-enricher --tail 10 2>&1 | tail -10

echo "--- метрики ---"
docker exec siem-enricher curl -s http://127.0.0.1:8080/metrics > /tmp/m.txt
grep -E 'events_enriched_total|sink_sent_total|events_failed' /tmp/m.txt | head -8 || true

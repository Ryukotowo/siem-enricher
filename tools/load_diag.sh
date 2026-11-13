#!/usr/bin/env bash
# Диагностика нагрузки: контейнеры, метрики, логи.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "--- контейнеры ---"
docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | head -10

echo "--- метрики ---"
docker exec siem-enricher sh -lc \
  'curl -s localhost:8080/metrics | grep -E "events_enriched_total|enrichment_duration_seconds_count|enrichment_duration_seconds_sum"'

echo "--- логи ---"
docker logs siem-enricher --tail 8 2>&1 | tail -8

echo "--- размер файла обогащения ---"
docker exec siem-enricher sh -lc 'wc -l /app/var/enriched_events.jsonl 2>/dev/null || echo нет файла'

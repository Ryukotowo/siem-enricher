#!/usr/bin/env bash
# Проверка работоспособности стенда.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "--- контейнеры ---"
docker compose ps --format 'table {{.Name}}\t{{.State}}' | head -5

echo "--- health внутри контейнера ---"
docker exec siem-enricher curl -s --max-time 5 http://127.0.0.1:8080/healthz | head -c 200
echo

echo "--- обогащённые события ---"
echo "файл: $(wc -l < var/enriched_events.jsonl 2>/dev/null || echo 0) строк"
echo "mock-siem: $(wc -l < var/mock_siem_received.jsonl 2>/dev/null || echo 0) строк"

echo "--- топик siem.enriched.events ---"
docker exec siem-enricher-redpanda rpk topic describe siem.enriched.events --brokers localhost:9092 2>/dev/null \
  | grep -iE 'high|partition' | head -3 || true

echo "--- метрики ---"
curl -s --max-time 5 http://localhost:8080/metrics | grep -E '^siem_enricher_(events_enriched|policy_decisions)' | head -6

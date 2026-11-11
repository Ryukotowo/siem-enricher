#!/usr/bin/env bash
# Пересборка образа сервиса и проверка, что конвейер читает поток.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

ENRICHER_ML=0 docker compose build enricher >/tmp/build.log 2>&1
tail -2 /tmp/build.log

docker compose up -d --force-recreate enricher >/tmp/up.log 2>&1
tail -2 /tmp/up.log

echo "--- ожидание ---"
for _ in $(seq 1 20); do
  sleep 5
  state=$(docker inspect -f '{{.State.Status}}' siem-enricher 2>/dev/null || echo unknown)
  if [ "$state" != "running" ]; then continue; fi
  ready=$(curl -s --max-time 3 http://localhost:8080/healthz || true)
  if [ -n "$ready" ]; then break; fi
done

echo "--- режим конвейера ---"
docker logs siem-enricher 2>&1 | grep -o '"run_pipeline": [a-z]*' | tail -1 || echo "не найден"

echo "--- поток событий ---"
sleep 10
echo "обогащено в файл: $(wc -l < var/enriched_events.jsonl 2>/dev/null || echo 0)"
echo "в mock-siem:      $(wc -l < var/mock_siem_received.jsonl 2>/dev/null || echo 0)"
echo "--- метрики ---"
curl -s --max-time 5 http://localhost:8080/metrics | grep -E '^siem_enricher_(events_enriched_total|policy_decisions_total)' | head -6 || true

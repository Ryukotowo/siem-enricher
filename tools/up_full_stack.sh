#!/usr/bin/env bash
# Поднять полный стенд и проверить адреса.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "=== поднимаю ядро и мониторинг ==="
docker compose up -d redpanda redis mock-siem enricher 2>&1 | tail -3
docker compose --profile observability up -d prometheus grafana 2>&1 | tail -3
docker compose --profile quickwit up -d quickwit 2>&1 | tail -2

echo "=== ожидание готовности ==="
for _ in $(seq 1 30); do
  sleep 4
  ok=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://localhost:8080/healthz || echo 000)
  if [ "$ok" = "200" ]; then break; fi
done

echo "=== контейнеры ==="
docker compose --profile observability --profile quickwit ps --format 'table {{.Name}}\t{{.State}}' | head -10

echo "=== публикую события ==="
docker exec siem-enricher sh -lc 'python /app/tools/generate_sample_events.py --scenario mixed --count 40 --out /tmp/g.jsonl >/dev/null 2>&1 && python /app/tools/kafka_tool.py publish --bootstrap redpanda:9092 --topic siem.raw.events --input /tmp/g.jsonl 2>&1 | tail -1'
sleep 10

echo "=== проверка адресов ==="
for url in \
  "http://localhost:8080/healthz" \
  "http://localhost:8080/ui" \
  "http://localhost:8080/metrics" \
  "http://localhost:9090/-/healthy" \
  "http://localhost:3000/api/health" \
  "http://localhost:7280/api/v1/version" \
  "http://localhost:8080/readyz"; do
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$url" || echo 000)
  echo "  $code  $url"
done

echo "=== панель ==="
curl -s --max-time 5 'http://localhost:8080/ui/events?limit=1' | head -c 200
echo
echo "=== метрики решений ==="
curl -s --max-time 5 http://localhost:8080/metrics | grep -E '^siem_enricher_policy_decisions_total' | head -5

#!/usr/bin/env bash
# Проверка дашборда Grafana и индекса Quickwit, при необходимости — создание и загрузка.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "=== Grafana: дашборд ==="
curl -s --max-time 5 http://localhost:3000/api/dashboards/uid/siem-enricher \
  | head -c 160
echo
echo "=== Prometheus: цель ==="
curl -s --max-time 5 'http://localhost:9090/api/v1/targets?state=active' \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for target in data['data']['activeTargets']:
    print(target['labels'].get('job'), target['health'], target['scrapeUrl'])
" 2>/dev/null | head -5

echo "=== Quickwit: индексы ==="
curl -s --max-time 5 http://localhost:7280/api/v1/indexes | python3 -c "
import json, sys
data = json.load(sys.stdin)
print([item.get('index_id') for item in data])
" 2>/dev/null || curl -s --max-time 5 http://localhost:7280/api/v1/indexes | head -c 200

echo "=== Quickwit: создаю индекс и загружаю события ==="
docker exec siem-enricher sh -lc 'python /app/tools/quickwit_demo.py --base http://quickwit:7280 --input /app/var/enriched_events.jsonl 2>&1 | tail -3' || true

echo "=== Quickwit: поиск ==="
curl -s --max-time 8 -X POST http://localhost:7280/api/v1/siem-enriched/search \
  -H 'Content-Type: application/json' -d '{"query": "*", "max_hits": 1}' \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('найдено:', data.get('num_hits'))
" 2>/dev/null || echo "поиск недоступен"

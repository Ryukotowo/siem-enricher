#!/usr/bin/env bash
# Список индексов Quickwit и проверка поиска по event_id.
set -e
echo "--- индексы ---"
curl -s http://localhost:7280/api/v1/indexes | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data:
    print(item.get('index_id') or item.get('index_config', {}).get('index_id'))
" 2>/dev/null || curl -s http://localhost:7280/api/v1/indexes | head -c 400
echo
echo "--- поиск по индексу siem-enriched ---"
curl -s -X POST "http://localhost:7280/api/v1/indexes/siem-enriched/search" \
  -H 'Content-Type: application/json' \
  -d '{"query": "*", "max_hits": 1}' | head -c 300
echo
echo "--- страница UI ---"
curl -s -o /dev/null -w "код %{http_code}\n" "http://localhost:7280/ui/search?indexId=siem-enriched"

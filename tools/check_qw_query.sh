#!/usr/bin/env bash
# Проверка формата запроса к Quickwit и вариантов ссылки.
set -e
BASE=http://localhost:7280

echo "--- какой путь поиска работает ---"
for path in "/api/v1/siem-enriched/search" "/api/v1/indexes/siem-enriched/search"; do
  code=$(curl -s -o /tmp/qw.json -w '%{http_code}' -X POST "$BASE$path" \
    -H 'Content-Type: application/json' -d '{"query": "*", "max_hits": 1}')
  echo "$path -> $code"
done

echo "--- запрос по event_id ---"
EVENT=$(curl -s -X POST "$BASE/api/v1/siem-enriched/search" \
  -H 'Content-Type: application/json' -d '{"query": "*", "max_hits": 1}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['hits'][0]['event_id'])" 2>/dev/null || echo "")
echo "event_id: $EVENT"

if [ -n "$EVENT" ]; then
  for q in "event_id:$EVENT" "event_id:\"$EVENT\""; do
    hits=$(curl -s -X POST "$BASE/api/v1/siem-enriched/search" \
      -H 'Content-Type: application/json' \
      -d "{\"query\": \"$q\", \"max_hits\": 3}" \
      | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('hits', [])))" 2>/dev/null || echo "err")
    echo "query [$q] -> hits $hits"
  done
fi

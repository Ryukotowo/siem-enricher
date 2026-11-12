#!/usr/bin/env bash
# Проверка цикла обратной связи: метки -> экспорт -> датасет -> dry-run обучения.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "=== 1. размечу несколько событий через API ==="
for event in $(curl -s --max-time 5 'http://localhost:8080/ui/events?limit=12' \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['events']:
    print(item['event_id'] + '|' + str(item.get('file')) + '|' + str(item.get('path')) + '|' + str(item.get('directory')) + '|' + str(item.get('sensitivity')) + '|' + str(item.get('decision')) + '|' + str(item.get('risk')))
"); do
  IFS='|' read -r event_id file path directory level decision risk <<< "$event"
  payload=$(python3 -c "
import json, sys
print(json.dumps({
    'event_id': sys.argv[1], 'label': 'confirmed', 'comment': 'проверка цикла',
    'file': sys.argv[2], 'path': sys.argv[3], 'directory': sys.argv[4],
    'level': sys.argv[5], 'decision': sys.argv[6], 'risk': float(sys.argv[7] or 0),
}, ensure_ascii=False))
" "$event_id" "$file" "$path" "$directory" "$level" "$decision" "$risk")
  curl -s --max-time 5 -X POST http://localhost:8080/ui/label \
    -H 'Content-Type: application/json' -H 'X-Analyst: tester' -d "$payload" > /dev/null
done
echo "  метки отправлены"

echo "=== 2. экспорт датасета ==="
curl -s --max-time 10 http://localhost:8080/ui/labels/export -o var/labels/dataset.jsonl
echo "  строк в датасете: $(wc -l < var/labels/dataset.jsonl)"
head -1 var/labels/dataset.jsonl | python3 -c "
import json, sys
row = json.loads(sys.stdin.readline())
print('  пример:', row['level'], '|', row['name'], '|', row['path'][:60])
"

echo "=== 3. dry-run обучения ==="
PYTHONPATH=src python3 tools/train_from_labels.py --input var/labels/dataset.jsonl --dry-run 2>&1 | tail -3

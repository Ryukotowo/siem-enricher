#!/usr/bin/env bash
# Долгая проверка потока: панель должна расти вместе с отправленными.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/demo/start \
  -H 'Content-Type: application/json' -d '{"interval": 0.5, "scenario": "mixed"}' > /dev/null
echo "поток запущен, ждём 30 секунд"
sleep 30

demo=$(curl -s --max-time 10 http://127.0.0.1:8081/ui/demo)
sent=$(echo "$demo" | python3 -c "import json,sys; print(json.load(sys.stdin)['sent'])")
total=$(curl -s --max-time 10 'http://127.0.0.1:8081/ui/events?limit=500' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['stats']['total'])")
echo "отправлено: $sent | в панели: $total"

curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/demo/stop -H 'Content-Type: application/json' -d '{}' > /dev/null
if [ "$total" -ge $((sent * 8 / 10)) ]; then
  echo "ОК: панель растёт вместе с потоком"
else
  echo "ПРОБЛЕМА: события схлопываются"
fi

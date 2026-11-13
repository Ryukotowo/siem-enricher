#!/usr/bin/env bash
# Проверка живого потока: запуск на 10 секунд, затем остановка.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

before=$(curl -s --max-time 10 'http://127.0.0.1:8081/ui/events?limit=500' | python3 -c "import json,sys; print(len(json.load(sys.stdin)['events']))")
echo "событий до запуска: $before"

echo "--- запускаю поток (интервал 1 с) ---"
curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/demo/start \
  -H 'Content-Type: application/json' -d '{"interval": 1, "scenario": "mixed"}'
echo

sleep 12

echo "--- состояние ---"
curl -s --max-time 10 http://127.0.0.1:8081/ui/demo
echo

after=$(curl -s --max-time 10 'http://127.0.0.1:8081/ui/events?limit=500' | python3 -c "import json,sys; print(len(json.load(sys.stdin)['events']))")
echo "событий в панели: $after (было $before)"

echo "--- останавливаю ---"
curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/demo/stop -H 'Content-Type: application/json' -d '{}'
echo

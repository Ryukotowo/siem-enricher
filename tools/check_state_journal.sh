#!/usr/bin/env bash
# Проверка журнала состояния: список и откат.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

echo "--- список состояний ---"
curl -s --max-time 10 http://127.0.0.1:8081/ui/state | head -c 400
echo

ID=$(curl -s --max-time 10 http://127.0.0.1:8081/ui/state \
  | python3 -c "import json,sys; data=json.load(sys.stdin)['states']; print(data[-1]['id'] if data else '')")
echo "--- откат на $ID ---"
curl -s --max-time 20 -X POST http://127.0.0.1:8081/ui/state/rollback \
  -H 'Content-Type: application/json' -H 'X-Analyst: admin' \
  -d "{\"state\": \"$ID\"}"
echo

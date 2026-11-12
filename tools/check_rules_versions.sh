#!/usr/bin/env bash
# Проверка версий правил: перезагрузка создаёт снимок, откат возвращает файл.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

docker compose up -d --force-recreate enricher 2>&1 | tail -1
sleep 30

echo "--- перезагрузка правил (создаёт снимок) ---"
curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/rules/reload
echo
echo "--- версии правил ---"
LIST=$(curl -s --max-time 5 http://127.0.0.1:8081/ui/rules/versions)
echo "$LIST" | head -c 300
echo

NAME=$(echo "$LIST" | python3 -c "import json,sys; data=json.load(sys.stdin)['versions']; print(data[0]['name'] if data else '')")
if [ -z "$NAME" ]; then
  echo "снимков нет — откат проверить нельзя"
  exit 0
fi

echo "--- откат на $NAME ---"
curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/rules/rollback \
  -H 'Content-Type: application/json' -d "{\"version\": \"$NAME\"}"
echo

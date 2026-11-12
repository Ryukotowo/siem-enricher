#!/usr/bin/env bash
# Пересборка сервиса и проверка новых эндпоинтов.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

docker compose build enricher 2>&1 | tail -1
docker compose up -d --force-recreate enricher 2>&1 | tail -1
sleep 30

for path in healthz ui/labels/export; do
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/$path")
  echo "$code  /$path"
done

echo "--- перезагрузка модели ---"
curl -s --max-time 10 -X POST http://127.0.0.1:8081/ui/model/reload
echo
echo "--- версии правил ---"
curl -s --max-time 5 http://127.0.0.1:8081/ui/rules/versions | head -c 300
echo

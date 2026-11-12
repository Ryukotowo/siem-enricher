#!/usr/bin/env bash
# Пересобрать сервис и проверить эндпоинты после изменений.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

ENRICHER_ML=0 docker compose build enricher 2>&1 | tail -1
docker compose up -d --force-recreate enricher 2>&1 | tail -1
sleep 30

for url in http://127.0.0.1:8081/healthz http://127.0.0.1:8081/ui/labels/export; do
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$url")
  echo "$code  $url"
done
code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8081/ui/rules/reload)
echo "$code  POST /ui/rules/reload"

echo "--- метки организации default ---"
curl -s --max-time 5 http://127.0.0.1:8081/ui/labels/export | head -1

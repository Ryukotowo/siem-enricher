#!/usr/bin/env bash
# Диагностика стенда: монтирования, состояние контейнеров, логи.
set -e
echo "--- mounts ---"
docker inspect siem-enricher --format '{{json .Mounts}}' | python3 -c "
import json,sys
for m in json.load(sys.stdin):
    print(m['Type'], m.get('Name') or m.get('Source'), '->', m['Destination'])
"
echo "--- /app/state внутри контейнера ---"
docker run --rm -v siem-enricher_state-data:/s alpine sh -c 'ls -ld /s; touch /s/probe && echo запись ок' 2>&1 | tail -2

echo "--- env контейнера ---"
docker inspect siem-enricher --format '{{json .Config.Env}}' | python3 -c "
import json,sys
for item in json.load(sys.stdin):
    if item.startswith(('PROVENANCE','AUDIT','CONFIG','KAFKA')):
        print(' ', item)
"
echo "--- логи (первые ошибки) ---"
docker logs siem-enricher 2>&1 | grep -m3 -E 'Error|error|OperationalError|sqlite' || true

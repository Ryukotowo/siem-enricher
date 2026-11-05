#!/bin/bash
# Подъём Quickwit и проверка готовности
set -u
docker rm -f siem-quickwit >/dev/null 2>&1
docker run -d --name siem-quickwit -p 7280:7280 quickwit/quickwit:0.8.1 run >/dev/null 2>&1

for attempt in $(seq 1 15); do
  sleep 3
  version=$(curl -s --max-time 3 http://localhost:7280/api/v1/version)
  if [ -n "$version" ]; then
    echo "version: $version"
    break
  fi
done

docker ps --filter name=siem-quickwit --format '{{.Names}} {{.Status}}'
echo "--- логи ---"
docker logs siem-quickwit 2>&1 | tail -4

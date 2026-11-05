#!/bin/bash
# Подъём Quickwit (если нужно) и прогон записи событий
set -u
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher || exit 1

if ! docker ps --format '{{.Names}}' | grep -q siem-quickwit; then
  docker rm -f siem-quickwit >/dev/null 2>&1
  docker run -d --name siem-quickwit -p 7280:7280 quickwit/quickwit:0.8.1 run >/dev/null 2>&1
  echo "контейнер запущен"
fi

ready=""
for attempt in $(seq 1 15); do
  sleep 3
  ready=$(curl -s --max-time 3 http://localhost:7280/api/v1/version)
  [ -n "$ready" ] && break
done

if [ -z "$ready" ]; then
  echo "!! Quickwit не поднялся"
  docker logs siem-quickwit 2>&1 | tail -5
  exit 1
fi
echo "Quickwit готов"

python3 tools/quickwit_demo.py

#!/usr/bin/env bash
# Нагрузочная проверка: 10 000 событий через Kafka.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

docker compose build enricher 2>&1 | tail -1
docker compose up -d --force-recreate enricher 2>&1 | tail -1
sleep 35

docker compose run --rm --no-deps --entrypoint python enricher \
  tools/load_test.py --count 10000 --batch 500 --base http://127.0.0.1:8080

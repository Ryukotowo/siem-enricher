#!/usr/bin/env bash
# Нагрузка: ждём готовности сервиса и запускаем измерение изнутри контейнера.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

for _ in $(seq 1 60); do
  if docker exec siem-enricher sh -lc 'curl -fsS -o /dev/null http://127.0.0.1:8080/healthz' 2>/dev/null; then
    break
  fi
  sleep 3
done

docker exec siem-enricher python tools/load_test.py \
  --count "${COUNT:-1000}" --batch "${BATCH:-200}" --base http://127.0.0.1:8080 2>&1 | tail -12

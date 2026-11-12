#!/usr/bin/env bash
# Единый движок: нативный dockerd в WSL. Docker Desktop не используется.
set -e

echo "=== 1. останавливаю нативный демон, если он в конфликте ==="
echo "$SUDO_PASS" | sudo -S pkill -f dockerd 2>/dev/null || true
sleep 3

echo "=== 2. запускаю docker через systemd/service ==="
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q docker.service; then
  echo "$SUDO_PASS" | sudo -S systemctl start docker 2>&1 | tail -2 || true
else
  echo "$SUDO_PASS" | sudo -S service docker start 2>&1 | tail -2 || true
fi

echo "=== 3. ждём движок ==="
for _ in $(seq 1 20); do
  if docker info >/dev/null 2>&1; then echo "docker готов"; break; fi
  sleep 3
done
docker context use default >/dev/null 2>&1 || true
docker info --format 'движок {{.ServerVersion}}, контейнеров {{.Containers}}, запущено {{.ContainersRunning}}'

echo "=== 4. состояние контейнеров до запуска ==="
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher
docker compose --profile observability --profile quickwit ps --format 'table {{.Name}}\t{{.State}}' 2>/dev/null | head -10 || true

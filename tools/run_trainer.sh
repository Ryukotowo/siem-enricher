#!/usr/bin/env bash
# Прогон обучения в контейнере тренера с сохранением журнала.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

LOG=/tmp/trainer_run.log
if docker compose --profile trainer run --rm trainer > "$LOG" 2>&1; then
  echo "код: 0"
else
  echo "код: $?"
fi

grep -E 'меток всего|обучение [0-9]+|регрессионный|отложенная:|регрессия:|прирост|изменение|модель' "$LOG" | tail -12

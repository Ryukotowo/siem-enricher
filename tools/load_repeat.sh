#!/usr/bin/env bash
# Три прогона по 1000 событий: медиана и разброс.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

for run in 1 2 3; do
  echo "--- прогон $run ---"
  bash tools/load_wait_run.sh 2>&1 | grep -E 'событий_в_секунду|потери|средняя_задержка|p95'
  sleep 3
done

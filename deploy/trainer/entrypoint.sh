#!/usr/bin/env bash
# Запуск дообучения внутри контейнера тренера.
#
# Переменные:
#   TENANT — организация (по умолчанию default)
#   INPUT  — файл датасета (по умолчанию var/labels/<tenant>/dataset.jsonl)
set -euo pipefail

TENANT="${TENANT:-default}"
if [ "$TENANT" = "default" ]; then
  INPUT="${INPUT:-var/labels/dataset.jsonl}"
else
  INPUT="${INPUT:-var/labels/$TENANT/dataset.jsonl}"
fi

if [ ! -f "$INPUT" ]; then
  echo "нет файла меток: $INPUT" >&2
  echo "выгрузите его из панели: curl -s http://localhost:8081/ui/labels/export -o $INPUT" >&2
  exit 2
fi

exec python tools/train_from_labels.py --input "$INPUT" --tenant "$TENANT" "$@"

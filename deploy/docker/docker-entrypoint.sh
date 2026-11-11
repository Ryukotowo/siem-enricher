#!/usr/bin/env sh
# Точка входа контейнера. Режим задаётся переменной ENRICHER_MODE:
#   serve   - поднять HTTP-сервис обогащения (по умолчанию)
#   run     - запустить конвейер "источник -> обогатитель -> приёмник" без HTTP
#   replay  - однократно обработать файл событий и завершиться
#   shell   - отладочная оболочка
set -eu

CONFIG="${CONFIG:-/app/config/config.docker.json}"
ENRICHER_MODE="${ENRICHER_MODE:-serve}"

echo "[entrypoint] mode=${ENRICHER_MODE} config=${CONFIG} python=$(python --version 2>&1)"

case "$ENRICHER_MODE" in
  serve)
    # RUN_PIPELINE=1 поднимает сервис вместе с чтением потока источника
    PIPELINE_FLAG=""
    if [ "${RUN_PIPELINE:-0}" = "1" ]; then PIPELINE_FLAG="--run-pipeline"; fi
    exec python -m siem_enricher serve --config "$CONFIG" \
      --host "${HTTP_HOST:-0.0.0.0}" --port "${HTTP_PORT:-8080}" $PIPELINE_FLAG
    ;;
  run)
    exec python -m siem_enricher run --config "$CONFIG"
    ;;
  replay)
    exec python -m siem_enricher replay --config "$CONFIG" \
      --input "${REPLAY_INPUT:?REPLAY_INPUT is required for replay mode}" \
      --output "${REPLAY_OUTPUT:-/app/var/enriched_events.jsonl}"
    ;;
  shell)
    exec /bin/sh
    ;;
  *)
    echo "[entrypoint] unknown ENRICHER_MODE: $ENRICHER_MODE" >&2
    exit 2
    ;;
esac

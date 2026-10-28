#!/bin/sh
# Подъём открытой SIEM (OpenSearch) для экспериментального стенда.
# Использование: wsl -e sh /mnt/c/.../scripts/stand_siem.sh [--down|--logs]
set -e

CONTAINER=siem-opensearch
IMAGE=opensearchproject/opensearch:2.15.0
PORT=9200

wait_ready() {
    i=0
    while [ "$i" -lt 60 ]; do
        status=$(curl -s -m 3 "http://localhost:${PORT}/_cluster/health" | tr ',' '\n' | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' | head -1)
        if [ -n "$status" ]; then
            echo "health: $status (попытка $((i + 1)))"
            return 0
        fi
        i=$((i + 1))
        sleep 3
    done
    echo "кластер не поднялся за 180 с"
    return 1
}

case "${1:-}" in
    --down)
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        echo "контейнер остановлен и удалён"
        exit 0
        ;;
    --logs)
        docker logs --tail 40 "$CONTAINER"
        exit 0
        ;;
esac

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
    -p "${PORT}:9200" \
    -e discovery.type=single-node \
    -e DISABLE_SECURITY_PLUGIN=true \
    -e DISABLE_INSTALL_DEMO_CONFIG=true \
    -e OPENSEARCH_INITIAL_ADMIN_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-LocalStand-ChangeMe1!}" \
    -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
    -e bootstrap.memory_lock=false \
    "$IMAGE" >/dev/null
echo "контейнер запущен: $CONTAINER"

if ! wait_ready; then
    echo "--- последние строки лога ---"
    docker logs --tail 20 "$CONTAINER" 2>&1
    exit 1
fi

curl -s "http://localhost:${PORT}" | head -12

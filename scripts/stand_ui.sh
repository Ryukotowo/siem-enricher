#!/bin/sh
# Стенд с веб-интерфейсом: OpenSearch + OpenSearch Dashboards.
#   wsl -e sh /mnt/c/.../scripts/stand_ui.sh          поднять стенд и открыть шаблоны индексов
#   wsl -e sh /mnt/c/.../scripts/stand_ui.sh --down   остановить всё
#   wsl -e sh /mnt/c/.../scripts/stand_ui.sh --status состояние контейнеров
set -e

NET=siem-net
OS_NAME=siem-opensearch
OSD_NAME=siem-dashboards
OS_IMAGE=opensearchproject/opensearch:2.15.0
OSD_IMAGE=opensearchproject/opensearch-dashboards:2.15.0
OS_PORT=9200
OSD_PORT=5601

wait_http() {
    url=$1
    label=$2
    i=0
    while [ "$i" -lt 90 ]; do
        if curl -s -m 3 "$url" >/dev/null 2>&1; then
            echo "$label готов (попытка $((i + 1)))"
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "$label не поднялся за 180 с"
    return 1
}

case "${1:-}" in
    --down)
        docker rm -f "$OSD_NAME" "$OS_NAME" >/dev/null 2>&1 || true
        echo "контейнеры остановлены"
        exit 0
        ;;
    --status)
        docker ps -a --filter "name=$OS_NAME" --filter "name=$OSD_NAME" \
            --format '{{.Names}}  {{.Status}}  {{.Ports}}'
        exit 0
        ;;
esac

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

# --- OpenSearch -------------------------------------------------------------
if [ -z "$(docker ps -q -f name=^${OS_NAME}$)" ]; then
    docker rm -f "$OS_NAME" >/dev/null 2>&1 || true
    echo "запускаю OpenSearch..."
    docker run -d --name "$OS_NAME" --network "$NET" -p "${OS_PORT}:9200" \
        -e discovery.type=single-node \
        -e DISABLE_SECURITY_PLUGIN=true \
        -e DISABLE_INSTALL_DEMO_CONFIG=true \
        -e OPENSEARCH_INITIAL_ADMIN_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-LocalStand-ChangeMe1!}" \
        -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
        "$OS_IMAGE" >/dev/null
fi
wait_http "http://localhost:${OS_PORT}/_cluster/health" "OpenSearch"

# --- OpenSearch Dashboards --------------------------------------------------
if [ -z "$(docker ps -q -f name=^${OSD_NAME}$)" ]; then
    docker rm -f "$OSD_NAME" >/dev/null 2>&1 || true
    echo "запускаю OpenSearch Dashboards (первый запуск качает образ, это долго)..."
    docker run -d --name "$OSD_NAME" --network "$NET" -p "${OSD_PORT}:5601" \
        -e "OPENSEARCH_HOSTS=[\"http://${OS_NAME}:9200\"]" \
        -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
        -e DISABLE_INSTALL_DEMO_CONFIG=true \
        "$OSD_IMAGE" >/dev/null
fi
wait_http "http://localhost:${OSD_PORT}/api/status" "Dashboards"

# --- Шаблоны индексов, чтобы события были видны сразу ------------------------
add_pattern() {
    uid=$1
    title=$2
    curl -s -X POST "http://localhost:${OSD_PORT}/api/saved_objects/index-pattern/${uid}" \
        -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
        -d "{\"attributes\":{\"title\":\"${title}\",\"timeFieldName\":\"@timestamp\"}}" >/dev/null 2>&1 || true
    echo "шаблон индекса: ${title}"
}

add_pattern enriched 'siem-enriched-events-*'
add_pattern alerts 'wazuh-alerts-*'

curl -s -X POST "http://localhost:${OSD_PORT}/api/opensearch-dashboards/settings" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -d '{"changes":{"defaultIndex":"enriched"}}' >/dev/null 2>&1 || true

echo ""
echo "Открой в браузере: http://localhost:${OSD_PORT}"
echo "  Discover -> шаблон 'siem-enriched-events-*' -> события обогащения"
echo "  Discover -> шаблон 'wazuh-alerts-*' -> исходные события"

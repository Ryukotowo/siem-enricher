#!/bin/bash
# Полная проверка: logcollector -> правило -> активное реагирование -> карантин
set -u
REPO="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"
cd "$REPO" || exit 1
IMAGE=wazuh/wazuh-manager:4.7.3
C=siem-wazuh

docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network siem-net -p 55000:55000 -p 1515:1515 $IMAGE >/dev/null 2>&1
sleep 30

docker cp deploy/wazuh/ossec_conf_snippet.xml $C:/tmp/snippet.xml
docker exec -i $C python3 - <<'PY'
from pathlib import Path
conf = Path("/var/ossec/etc/ossec.conf")
snippet = Path("/tmp/snippet.xml").read_text(encoding="utf-8")
text = conf.read_text(encoding="utf-8")
if "<name>quarantine</name>" not in text:
    index = text.find("</ossec_config>")
    conf.write_text(text[:index] + snippet + "\n" + text[index:], encoding="utf-8")
    print("conf patched")
PY

docker cp deploy/wazuh/local_rules.xml $C:/var/ossec/etc/rules/local_rules.xml
docker cp deploy/wazuh/quarantine.sh $C:/var/ossec/active-response/bin/quarantine.sh
docker exec $C chmod 750 /var/ossec/active-response/bin/quarantine.sh
docker exec $C chown root:wazuh /var/ossec/active-response/bin/quarantine.sh

docker exec $C touch /var/ossec/test_events.log
docker exec $C /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
sleep 25

echo "=== подаю событие через файл ==="
docker exec $C sh -c "echo 'зарплатная ведомость' > /tmp/secret.txt; ls -l /tmp/secret.txt"
docker exec $C sh -c "printf '%s\n' '{\"dlp\":{\"decision\":\"block\",\"file\":\"/tmp/secret.txt\",\"rule\":\"POL-013\"}}' >> /var/ossec/test_events.log"
sleep 12

echo "=== журнал активного реагирования ==="
docker exec $C sh -c "tail -8 /var/ossec/logs/active-responses.log 2>&1 || echo 'нет журнала'"
echo "=== карантин ==="
docker exec $C sh -c "ls -l /var/ossec/quarantine 2>&1 || echo 'пусто'"
echo "=== исходный файл ==="
docker exec $C sh -c "ls -l /tmp/secret.txt 2>&1 || echo 'перемещён в карантин'"
echo "=== алерт ==="
docker exec $C sh -c "grep -c dlp /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0"

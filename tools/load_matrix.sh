#!/usr/bin/env bash
# Матрица нагрузочных измерений: три конфигурации по 1000 событий.
set -e
cd /mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher

CONFIG=config/config.docker.json
BACKUP=$(mktemp)
cp "$CONFIG" "$BACKUP"

restore() {
  cp "$BACKUP" "$CONFIG"
  docker compose up -d --force-recreate enricher >/dev/null 2>&1
  sleep 30
}
trap restore EXIT

run_case() {
  local name="$1"
  echo "=== $name ==="
  docker exec siem-enricher python tools/load_test.py \
    --count 1000 --batch 200 --base http://127.0.0.1:8080 2>&1 | tail -11
  docker exec siem-enricher cat /app/var/load_report.json > "var/load_${name}.json"
}

python3 - "$CONFIG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
for sink in data["sink"]["options"]["sinks"]:
    if sink["type"] == "webhook":
        sink["options"]["batch_size"] = 50
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

docker compose up -d --force-recreate enricher >/dev/null 2>&1
sleep 30
run_case "full"

python3 - "$CONFIG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["sink"] = {"type": "file_jsonl",
                "options": {"path": "/app/var/enriched_events.jsonl", "mode": "append"}}
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

docker compose up -d --force-recreate enricher >/dev/null 2>&1
sleep 30
run_case "file-only"

python3 - "$CONFIG" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["provenance"]["backend"] = "memory"
data["sink"]["options"] if False else None
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

docker compose up -d --force-recreate enricher >/dev/null 2>&1
sleep 30
run_case "memory-provenance"

echo "готово"

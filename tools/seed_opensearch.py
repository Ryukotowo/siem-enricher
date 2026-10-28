"""Засев открытой SIEM (OpenSearch / Wazuh Indexer) синтетическими событиями."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from tools.generate_sample_events import build_events  # noqa: E402

ALERTS_TEMPLATE = {
    "index_patterns": ["wazuh-alerts-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "date_detection": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "agent": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}},
                "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"}}},
                "data": {"type": "object", "enabled": True},
            },
        },
    },
}

ENRICHED_TEMPLATE = {
    "index_patterns": ["siem-enriched-events-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "date_detection": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "event_id": {"type": "keyword"},
                "data_sensitivity": {"type": "keyword"},
                "risk_score": {"type": "float"},
                "risk_severity": {"type": "keyword"},
                "policy_decision": {"type": "keyword"},
                "provenance_depth": {"type": "integer"},
            },
        },
    },
}


def request(method: str, url: str, payload: Any | None = None, timeout: float = 30.0) -> tuple[int, str]:
    """Выполнить HTTP-запрос и вернуть код ответа и текст."""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        if isinstance(payload, (dict, list)):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        else:
            data = str(payload).encode("utf-8")
            headers["Content-Type"] = "application/x-ndjson"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return 0, f"нет связи: {exc.reason}"


def wait_for_cluster(url: str, attempts: int = 60, delay: float = 2.0) -> bool:
    """Дождаться готовности кластера."""
    import time

    for attempt in range(1, attempts + 1):
        code, body = request("GET", f"{url}/_cluster/health?wait_for_status=yellow&timeout=5s")
        if code == 200 and '"status"' in body:
            print(f"кластер готов (попытка {attempt})")
            return True
        print(f"  ожидание кластера: попытка {attempt}/{attempts} (код {code})")
        time.sleep(delay)
    return False


def install_templates(url: str) -> bool:
    """Создать индексные шаблоны для исходных и обогащённых событий."""
    ok = True
    for name, template in (("wazuh-alerts", ALERTS_TEMPLATE), ("siem-enriched", ENRICHED_TEMPLATE)):
        code, body = request("PUT", f"{url}/_index_template/{name}", template)
        if code in (200, 201):
            print(f"шаблон установлен: {name}")
        else:
            print(f"!! шаблон {name}: код {code}, {body[:200]}")
            ok = False
    return ok


def index_events(url: str, events: list[dict[str, Any]], index_prefix: str = "wazuh-alerts") -> int:
    """Загрузить события в индекс одним bulk-запросом."""
    today = datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{index_prefix}-{today}"
    lines: list[str] = []
    for event in events:
        lines.append(json.dumps({"index": {"_index": index_name, "_id": event.get("id")}}, ensure_ascii=False))
        lines.append(json.dumps(event, ensure_ascii=False))
    body = "\n".join(lines) + "\n"
    code, response = request("POST", f"{url}/_bulk?refresh=true", body)
    if code not in (200, 201):
        print(f"!! bulk-загрузка: код {code}, {response[:300]}")
        return 0
    try:
        result = json.loads(response)
    except json.JSONDecodeError:
        return 0
    if result.get("errors"):
        print("!! часть документов не загружена")
    count = int(result.get("items") and len(result["items"]) or 0)
    print(f"загружено событий: {count} -> {index_name}")
    return count


def verify(url: str) -> int:
    """Проверить наличие исходных и обогащённых документов."""
    code, body = request("GET", f"{url}/_cat/indices?format=json")
    if code != 200:
        print(f"!! не удалось получить список индексов: код {code}")
        return 1
    indices = [item.get("index", "") for item in json.loads(body or "[]")]
    alerts = sorted(name for name in indices if name.startswith("wazuh-alerts"))
    enriched = sorted(name for name in indices if name.startswith("siem-enriched-events"))
    print(f"индексы с исходными событиями: {alerts or 'нет'}")
    print(f"индексы с обогащёнными событиями: {enriched or 'нет'}")
    if not enriched:
        print("обогащённые события пока не записаны (сервис не обработал поток)")
        return 1

    for index in enriched[-1:]:
        code, body = request("GET", f"{url}/{index}/_search?size=1&sort=@timestamp:desc")
        if code != 200:
            continue
        hits = json.loads(body)["hits"]["hits"]
        if not hits:
            continue
        document = hits[0]["_source"]
        print(f"\nпример обогащённого события из {index}:")
        for key in ("event_id", "action", "data_sensitivity", "sensitivity_confidence",
                    "provenance_depth", "risk_score", "risk_severity", "policy_decision",
                    "policy_rule_ids", "external_destinations_count"):
            if key in document:
                print(f"  {key}: {document[key]}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Засев открытой SIEM (OpenSearch) событиями")
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--scenario", default="mixed",
                        choices=["benign", "exfiltration", "ransomware", "mixed"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--index-prefix", default="wazuh-alerts")
    parser.add_argument("--templates-only", action="store_true")
    parser.add_argument("--verify", action="store_true", help="Проверить наличие обогащённых документов")
    parser.add_argument("--no-wait", action="store_true", help="Не ждать готовности кластера")
    args = parser.parse_args(argv)

    if args.verify:
        return verify(args.url)

    if not args.no_wait and not wait_for_cluster(args.url):
        print("!! кластер не готов")
        return 1
    if not install_templates(args.url):
        return 1
    if args.templates_only:
        return 0

    events = build_events(scenario=args.scenario, count=args.count, seed=args.seed)
    loaded = index_events(args.url, events, args.index_prefix)
    return 0 if loaded else 1


if __name__ == "__main__":
    raise SystemExit(main())

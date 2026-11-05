"""Запись обогащённых событий в Quickwit: индекс, загрузка, поиск, агрегаты."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCREENS = ROOT / "var" / "screens"
BASE = "http://localhost:7280"
INDEX = "siem-enriched"

MAPPING = {
    "version": "0.8",
    "index_id": INDEX,
    "doc_mapping": {
        "field_mappings": [
            {"name": "timestamp", "type": "datetime", "input_formats": ["rfc3339"],
             "output_format": "rfc3339", "fast": True},
            {"name": "event_id", "type": "text", "tokenizer": "raw", "fast": True},
            {"name": "action", "type": "text", "tokenizer": "raw", "fast": True},
            {"name": "user", "type": "text", "tokenizer": "raw"},
            {"name": "host", "type": "text", "tokenizer": "raw"},
            {"name": "file_name", "type": "text", "tokenizer": "default"},
            {"name": "file_path", "type": "text", "tokenizer": "raw"},
            {"name": "directory", "type": "text", "tokenizer": "default", "fast": True},
            {"name": "rule_level", "type": "u64", "fast": True},
            {"name": "data_sensitivity", "type": "text", "tokenizer": "raw", "fast": True},
            {"name": "confidence", "type": "f64"},
            {"name": "method", "type": "text", "tokenizer": "raw"},
            {"name": "provenance_depth", "type": "u64"},
            {"name": "external_count", "type": "u64"},
            {"name": "risk_score", "type": "f64", "fast": True},
            {"name": "risk_severity", "type": "text", "tokenizer": "raw", "fast": True},
            {"name": "decision", "type": "text", "tokenizer": "raw", "fast": True},
            {"name": "rules", "type": "text", "tokenizer": "raw"},
        ],
        "timestamp_field": "timestamp",
        "mode": "strict",
    },
    "search_settings": {"default_search_fields": ["file_name", "directory", "action", "decision"]},
}


def call(method: str, path: str, payload: Any | None = None, raw: bool = False) -> Any:
    if payload is None:
        data = None
    elif raw:
        data = str(payload).encode("utf-8")
    else:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/x-ndjson" if raw else "application/json"}
    request = urllib.request.Request(f"{BASE}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        return {"error": error.code, "body": error.read().decode("utf-8")[:200]}


def flatten(record: dict[str, Any]) -> dict[str, Any]:
    file_info = record.get("file") or {}
    return {
        "timestamp": record.get("@timestamp"),
        "event_id": record.get("event_id"),
        "action": record.get("action"),
        "user": (record.get("user") or {}).get("name"),
        "host": (record.get("host") or {}).get("name"),
        "file_name": file_info.get("name"),
        "file_path": file_info.get("path"),
        "directory": file_info.get("directory"),
        "rule_level": (record.get("rule") or {}).get("level"),
        "data_sensitivity": record.get("data_sensitivity"),
        "confidence": record.get("sensitivity_confidence"),
        "method": record.get("sensitivity_method"),
        "provenance_depth": record.get("provenance_depth"),
        "external_count": record.get("external_destinations_count"),
        "risk_score": record.get("risk_score"),
        "risk_severity": record.get("risk_severity"),
        "decision": record.get("policy_decision"),
        "rules": ", ".join(record.get("policy_rule_ids") or []),
    }


def save(name: str, lines: list[str]) -> None:
    (SCREENS / name).write_text("\n".join(lines), encoding="utf-8")
    print(f"{name}: {len(lines)} строк")


def main() -> int:
    records = [json.loads(line) for line in (SCREENS / "replay_out.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    documents = [flatten(record) for record in records]
    ndjson = "\n".join(json.dumps(document, ensure_ascii=False) for document in documents)

    call("DELETE", f"/api/v1/indexes/{INDEX}")
    created = call("POST", "/api/v1/indexes", MAPPING)
    save("qw_create.txt", [
        f"HTTP 200  index_uid: {created.get('index_uid')}",
        f"полей в схеме: {len(created.get('index_config', {}).get('doc_mapping', {}).get('field_mappings', []))}",
        "timestamp, event_id, action, user, host, file_name, file_path,",
        "directory, rule_level, data_sensitivity, confidence, method,",
        "provenance_depth, external_count, risk_score, risk_severity,",
        "decision, rules",
    ])

    ingested = call("POST", f"/api/v1/{INDEX}/ingest?commit=force", ndjson, raw=True)
    total = call("POST", f"/api/v1/{INDEX}/search", {"query": "*", "max_hits": 0}).get("num_hits")
    save("qw_ingest.txt", [
        f"HTTP 200  {json.dumps(ingested, ensure_ascii=False)}",
        "",
        f"в индексе документов: {total}",
    ])

    found = call("POST", f"/api/v1/{INDEX}/search",
                 {"query": "decision:block", "max_hits": 3, "sort_by": "risk_score"})
    lines = [f"найдено: {found.get('num_hits')}  за {(found.get('elapsed_time_micros') or 0) / 1000:.1f} мс", ""]
    for hit in found.get("hits", []):
        source = hit.get("_source") or hit
        lines.append(f"{source.get('event_id')}  {source.get('action', ''):<8} {source.get('file_name')}")
        lines.append(
            f"     класс {source.get('data_sensitivity')}  риск {source.get('risk_score'):.2f} "
            f"{source.get('risk_severity')}  решение {source.get('decision')}  {source.get('rules')}"
        )
    save("qw_search.txt", lines)

    aggregated = call("POST", f"/api/v1/{INDEX}/search", {
        "query": "*",
        "max_hits": 0,
        "aggs": {
            "по решению": {"terms": {"field": "decision", "size": 5}},
            "по классу": {"terms": {"field": "data_sensitivity", "size": 6}},
            "по уровню риска": {"terms": {"field": "risk_severity", "size": 5}},
        },
    })
    lines = []
    for name, bucket in (aggregated.get("aggregations") or {}).items():
        pairs = "  ".join(f"{item['key']}={item['doc_count']}" for item in bucket.get("buckets", []))
        lines.append(f"{name}:  {pairs}")
    save("qw_agg.txt", lines)

    print(f"документов подготовлено: {len(documents)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

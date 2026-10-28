"""Прогон типовых правил обнаружения реальным движком OpenSearch."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from tools.experiment_eval import confusion, quality, wilson  # noqa: E402

RULES_DIR = PROJECT_ROOT / "rules" / "sigma"
INDEX = "baseline-events"

SENSITIVE = ["зарплат", "ведомост", "паспорт", "снилс", "анкет", "договор", "клиент",
             "счет", "счёт", "отчет", "отчёт", "финанс", "диагноз", "медиц",
             "приказ", "payroll", "salary", "invoice", "contract", "customer"]
SECRET_EXT = [".kdbx", ".pem", ".key", ".env"]
PROTECTED_DIRS = ["\\hr\\", "\\бухгалтер", "\\юридическ", "\\клиент", "\\медицин", "\\finance", "\\legal"]
REMOVABLE_PREFIX = ["e:\\", "f:\\", "g:\\"]

# (имя файла, критичное ли правило, текст Sigma-правила)
RULES: list[tuple[str, bool, str]] = [
    ("r1_keyword_in_filename.yml", False, f"""
title: Ключевое слово в имени файла при действии с данными
id: 5f1a0001-0000-4000-8000-000000000001
status: experimental
description: Типовое правило DLP на ключевые слова в имени файла
logsource:
  category: file_event
detection:
  selection:
    file.name|contains: {json.dumps(SENSITIVE, ensure_ascii=False)}
    event.action: [upload, send, copy, move]
  condition: selection
level: high
"""),
    ("r2_secret_extension.yml", True, f"""
title: Файл с защищённым расширением
id: 5f1a0002-0000-4000-8000-000000000002
status: experimental
logsource:
  category: file_event
detection:
  selection:
    file.name|endswith: {json.dumps(SECRET_EXT)}
  condition: selection
level: critical
"""),
    ("r3_protected_directory.yml", False, f"""
title: Обращение к файлу в защищённом каталоге
id: 5f1a0003-0000-4000-8000-000000000003
status: experimental
logsource:
  category: file_event
detection:
  selection_dir:
    file.path|contains: {json.dumps(PROTECTED_DIRS, ensure_ascii=False)}
  selection_action:
    event.action: [upload, send, copy, move, archive, read]
  condition: selection_dir and selection_action
level: medium
"""),
    ("r4_external_destination.yml", True, """
title: Отправка файла во внешний адрес
id: 5f1a0004-0000-4000-8000-000000000004
status: experimental
logsource:
  category: file_event
detection:
  selection_action:
    event.action: [upload, send]
  selection_dest:
    destination.ip|exists: true
  condition: selection_action and selection_dest
level: critical
"""),
    ("r5_encryption.yml", True, """
title: Шифрование файлов
id: 5f1a0005-0000-4000-8000-000000000005
status: experimental
logsource:
  category: file_event
detection:
  selection:
    event.action: encrypt
  condition: selection
level: critical
"""),
    ("r6_archive_to_external.yml", True, f"""
title: Архивирование с внешним получателем или на носитель
id: 5f1a0006-0000-4000-8000-000000000006
status: experimental
logsource:
  category: file_event
detection:
  selection_action:
    event.action: archive
  selection_place:
    file.path|startswith: {json.dumps(REMOVABLE_PREFIX)}
  condition: selection_action and selection_place
level: critical
"""),
    ("r7_mass_copy.yml", True, """
title: Массовое обращение к файлам
id: 5f1a0007-0000-4000-8000-000000000007
status: experimental
logsource:
  category: file_event
detection:
  selection:
    files_count|gte: 10
  condition: selection
level: critical
"""),
    ("r8_siem_rule_level.yml", False, """
title: Уровень правила SIEM не ниже десяти
id: 5f1a0008-0000-4000-8000-000000000008
status: experimental
logsource:
  category: file_event
detection:
  selection:
    rule.level|gte: 10
  condition: selection
level: high
"""),
    ("r9_copy_to_removable.yml", True, f"""
title: Копирование на съёмный носитель
id: 5f1a0009-0000-4000-8000-000000000009
status: experimental
logsource:
  category: file_event
detection:
  selection_action:
    event.action: [copy, move, archive]
  selection_place:
    file.path|startswith: {json.dumps(REMOVABLE_PREFIX)}
  condition: selection_action and selection_place
level: critical
"""),
    ("r10_rename_high_level.yml", False, """
title: Переименование файла при высоком уровне правила
id: 5f1a0010-0000-4000-8000-000000000010
status: experimental
logsource:
  category: file_event
detection:
  selection:
    event.action: rename
    rule.level|gte: 10
  condition: selection
level: medium
"""),
]


def _wildcard(field: str, pattern: str) -> dict[str, Any]:
    # обратный слэш в путях Windows — escape-символ Lucene, его нужно удвоить
    escaped = pattern.lower().replace("\\", "\\\\")
    return {"wildcard": {field: {"value": escaped, "case_insensitive": True}}}


def _clause(key: str, value: Any) -> dict[str, Any]:
    field, _, modifier = key.partition("|")
    if modifier == "exists":
        return {"exists": {"field": field}} if value else {"bool": {"must_not": [{"exists": {"field": field}}]}}
    if modifier == "gte":
        return {"range": {field: {"gte": value}}}
    values = value if isinstance(value, list) else [value]
    if modifier == "contains":
        clauses = [_wildcard(field, f"*{str(item).lower()}*") for item in values]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    if modifier == "endswith":
        clauses = [_wildcard(field, f"*{str(item).lower()}") for item in values]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    if modifier == "startswith":
        clauses = [_wildcard(field, f"{str(item).lower()}*") for item in values]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    if len(values) > 1:
        return {"terms": {field: values}}
    return {"term": {field: values[0]}}


def rule_to_query(rule: dict[str, Any]) -> dict[str, Any]:
    """Преобразовать Sigma-правило в запрос OpenSearch DSL."""
    detection = rule["detection"]
    condition = str(detection["condition"])
    selections = {name: value for name, value in detection.items() if name != "condition"}

    def build(name: str) -> dict[str, Any]:
        body = selections[name]
        if isinstance(body, list):
            return {"bool": {"must": [_clause_entry(item) for item in body]}}
        return {"bool": {"must": [_clause(key, value) for key, value in body.items()]}}

    parts = [token.strip() for token in condition.replace(" and ", "\n").splitlines() if token.strip()]
    must: list[dict[str, Any]] = []
    must_not: list[dict[str, Any]] = []
    for index, token in enumerate(parts):
        negated = token.startswith("not ")
        name = token[4:].strip() if negated else token
        query = build(name)
        (must_not if negated else must).append(query)
        if index == 0 and not parts:
            break
    body: dict[str, Any] = {"must": must}
    if must_not:
        body["must_not"] = must_not
    return {"bool": body}


def _clause_entry(item: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in item.items():
        part = _clause(key, value)
        result.update(part)
    return result


def request(method: str, url: str, payload: Any | None = None, timeout: float = 30.0,
            raw: bool = False) -> Any:
    if payload is None:
        data = None
    elif raw:
        data = str(payload).encode("utf-8")
    else:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    content_type = "application/x-ndjson" if raw else "application/json"
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": content_type})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def event_document(raw: dict[str, Any]) -> dict[str, Any]:
    data = raw.get("data") or {}
    eventdata = (data.get("win") or {}).get("eventdata") or {}
    paths: list[str] = []
    for key in ("targetFilename", "sourceFilename"):
        value = eventdata.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    plural = eventdata.get("targetFilenames")
    if isinstance(plural, str):
        paths.extend(part.strip() for part in plural.split(";") if part.strip())

    names = [path.replace("\\", "/").rsplit("/", 1)[-1] for path in paths]
    document = {
        "event.action": str(data.get("action") or "unknown").lower(),
        "file.name": names,
        "file.path": paths,
        "files_count": len(paths),
        "rule.level": int((raw.get("rule") or {}).get("level", 0)),
        "x_incident": raw.get("x_label") == "incident",
        "x_kind": raw.get("x_kind"),
    }
    if eventdata.get("destinationIp"):
        document["destination.ip"] = eventdata["destinationIp"]
    if eventdata.get("destinationUrl"):
        document["destination.url"] = eventdata["destinationUrl"]
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Типовые правила Sigma на движке OpenSearch")
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--dataset", default="var/experiment/dataset.jsonl")
    parser.add_argument("--out", default="var/experiment/report_sigma_engine")
    args = parser.parse_args()

    RULES_DIR.mkdir(parents=True, exist_ok=True)
    loaded: list[tuple[str, bool, dict[str, Any]]] = []
    for filename, critical, text in RULES:
        (RULES_DIR / filename).write_text(text.strip() + "\n", encoding="utf-8")
        loaded.append((filename, critical, yaml.safe_load(text)))
    print(f"правил Sigma подготовлено: {len(loaded)} -> {RULES_DIR}")

    try:
        request("DELETE", f"{args.url}/{INDEX}")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    request("PUT", f"{args.url}/{INDEX}", {
        "settings": {"analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}},
        "mappings": {"properties": {
            "event.action": {"type": "keyword", "normalizer": "lc"},
            "file.name": {"type": "keyword", "normalizer": "lc"},
            "file.path": {"type": "keyword", "normalizer": "lc"},
            "destination.ip": {"type": "keyword", "normalizer": "lc"},
            "destination.url": {"type": "keyword", "normalizer": "lc"},
            "rule.level": {"type": "integer"},
            "files_count": {"type": "integer"},
            "x_incident": {"type": "boolean"},
            "x_kind": {"type": "keyword"},
        }}
    })
    raw_events = [json.loads(line) for line in (PROJECT_ROOT / args.dataset).read_text(encoding="utf-8").splitlines() if line.strip()]
    lines: list[str] = []
    for index, raw in enumerate(raw_events):
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": str(index)}}))
        lines.append(json.dumps(event_document(raw), ensure_ascii=False))
    request("POST", f"{args.url}/_bulk?refresh=true", "\n".join(lines) + "\n", raw=True)
    total = request("GET", f"{args.url}/{INDEX}/_count")["count"]
    print(f"проиндексировано событий: {total}")

    hits_by_rule: dict[str, set[int]] = {}
    queries: dict[str, Any] = {}
    for filename, _, rule in loaded:
        query = rule_to_query(rule)
        queries[str(rule["title"])] = query
        response = request("POST", f"{args.url}/{INDEX}/_search",
                           {"query": query, "size": 1000, "_source": ["x_incident"]})
        hits_by_rule[str(rule["title"])] = {int(hit["_id"]) for hit in response["hits"]["hits"]}

    critical_titles = {str(rule["title"]) for _, critical, rule in loaded if critical}
    incidents = {index for index, raw in enumerate(raw_events) if raw.get("x_label") == "incident"}

    def evaluate(selected: set[int]) -> dict[str, Any]:
        truth = [index in incidents for index in range(len(raw_events))]
        predicted = [index in selected for index in range(len(raw_events))]
        stats = confusion(predicted, truth)
        result = {"stats": stats, **{key: round(value, 4) for key, value in quality(stats).items()}}
        result["alerts"] = len(selected)
        result["prevented"] = sum(1 for index in selected if index in incidents)
        return result

    alert_union = set().union(*hits_by_rule.values()) if hits_by_rule else set()
    critical_union = set().union(*[hits for title, hits in hits_by_rule.items() if title in critical_titles]) if critical_titles else set()

    report = {
        "engine": "OpenSearch",
        "indexed": total,
        "incidents": len(incidents),
        "benign": len(raw_events) - len(incidents),
        "rules": [
            {
                "title": str(rule["title"]),
                "file": filename,
                "critical": critical,
                "hits": len(hits_by_rule[str(rule["title"])]),
                "query": queries[str(rule["title"])],
            }
            for filename, critical, rule in loaded
        ],
        "alert_only": evaluate(alert_union),
        "with_blocking": evaluate(alert_union & critical_union) if critical_union else evaluate(set()),
        "recall_ci": [round(v, 4) for v in wilson(evaluate(alert_union)["stats"]["tp"], len(incidents))],
    }

    target = PROJECT_ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nинцидентов: {report['incidents']}, легитимных: {report['benign']}")
    print(f"{'показатель':<26}{'оповещение':>14}{'с блокировкой':>16}")
    for key, label in (("recall", "полнота"), ("precision", "точность"), ("fpr", "доля ложных"),
                       ("f1", "F1"), ("alerts", "тревог"), ("prevented", "предотвращено")):
        print(f"{label:<26}{report['alert_only'][key]:>14}{report['with_blocking'][key]:>16}")
    print("\nсрабатывания по правилам:")
    for item in report["rules"]:
        mark = "critical" if item["critical"] else "—"
        print(f"  {item['title'][:52]:<54}{item['hits']:>4}  {mark}")
    print(f"\nотчёт: {target.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

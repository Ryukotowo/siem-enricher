"""Сбор реальных данных для визуальных слайдов."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402

OUT = ROOT / "var" / "demo" / "panels"
KEEP_FIELDS = [
    "event_id", "timestamp", "action", "user_name", "host_name",
    "files_count", "data_sensitivity", "classification_confidence",
    "provenance_depth", "external_destinations_count", "risk_score",
    "risk_severity", "policy_decision", "policy_rule_ids", "tags",
]


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    OUT.mkdir(parents=True, exist_ok=True)
    pipeline = EnrichmentPipeline.from_config(
        load_config(ROOT / "config/config.local.json"), in_memory_store=True
    )

    events = [json.loads(line) for line in (ROOT / "var/experiment/dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    incident = next(event for event in events if event.get("x_label") == "incident" and "usb" in str(event.get("x_kind")))

    raw = incident
    document = pipeline.enrich(pipeline.normalize("demo", raw)).document or {}

    raw_view = {
        "rule.level": (raw.get("rule") or {}).get("level"),
        "data.action": (raw.get("data") or {}).get("action"),
        "agent.name": (raw.get("agent") or {}).get("name"),
        "eventdata.targetFilename": ((raw.get("data") or {}).get("win") or {}).get("eventdata", {}).get("targetFilename"),
        "eventdata.sourceFilename": ((raw.get("data") or {}).get("win") or {}).get("eventdata", {}).get("sourceFilename"),
        "eventdata.destinationIp": ((raw.get("data") or {}).get("win") or {}).get("eventdata", {}).get("destinationIp"),
    }

    enriched_view = {key: document.get(key) for key in KEEP_FIELDS if document.get(key) is not None}
    enriched_view["policy_triggers"] = document.get("policy_decision")

    (OUT / "raw.json").write_text(json.dumps(raw_view, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "enriched.json").write_text(json.dumps(enriched_view, ensure_ascii=False, indent=2), encoding="utf-8")

    audit = ROOT / "var" / "logs" / "policy_audit.jsonl"
    if audit.exists():
        lines = audit.read_text(encoding="utf-8").strip().splitlines()[-3:]
        short = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            short.append({
                "event_id": record.get("event_id", "")[:8],
                "decision": record.get("decision"),
                "rules": record.get("policy_rule_ids") or record.get("rule_ids"),
                "risk": record.get("risk_score"),
            })
        (OUT / "audit.json").write_text(json.dumps(short, ensure_ascii=False, indent=2), encoding="utf-8")
        compact = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            parts = [str(record.get("kind", "")), str(record.get("rule_id", ""))]
            if record.get("decision"):
                parts.append(str(record["decision"]))
            if record.get("mode"):
                parts.append("mode=" + str(record["mode"]))
            if record.get("risk_score") is not None:
                parts.append("risk=" + str(record["risk_score"]))
            compact.append("  ".join(part for part in parts if part))
        (OUT / "audit.txt").write_text("\n".join(compact), encoding="utf-8")
        print(f"журнал аудита: {len(short)} записей")
    print(f"панели сохранены в {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

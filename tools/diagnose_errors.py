"""Разбор остаточных ошибок: какие правила дают ложные срабатывания и что не блокируется."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402

DATASET = ROOT / "var" / "experiment" / "dataset.jsonl"


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    pipeline = EnrichmentPipeline.from_config(
        load_config(ROOT / "config/config.local.json"), in_memory_store=True
    )

    benign: dict[str, Counter] = defaultdict(Counter)
    benign_rules: dict[str, Counter] = defaultdict(Counter)
    incidents: dict[str, Counter] = defaultdict(Counter)
    incident_rules: dict[str, Counter] = defaultdict(Counter)

    for line in DATASET.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        event = pipeline.normalize("diag", raw)
        document = pipeline.enrich(event).document or {}
        kind = raw["x_kind"]
        decision = document.get("policy_decision")
        rules = document.get("policy_rule_ids") or []
        level = document.get("data_sensitivity")
        target = benign if raw["x_label"] == "benign" else incidents
        target_rules = benign_rules if raw["x_label"] == "benign" else incident_rules
        target[kind][f"{decision}/{level}"] += 1
        for rule in rules:
            target_rules[kind][rule] += 1

    print("=== ЛЕГИТИМНЫЕ: решение/класс и сработавшие правила ===")
    for kind in sorted(benign):
        print(f"{kind}:")
        print(f"   решения: {dict(benign[kind])}")
        print(f"   правила: {dict(benign_rules[kind])}")

    print("\n=== ИНЦИДЕНТЫ: решение/класс и сработавшие правила ===")
    for kind in sorted(incidents):
        decisions = dict(incidents[kind])
        prevented = sum(count for key, count in incidents[kind].items() if key.startswith(("block", "mask")))
        total = sum(incidents[kind].values())
        mark = "OK" if prevented == total else "НЕ БЛОКИРУЕТСЯ"
        print(f"{kind}: {mark} ({prevented}/{total})")
        print(f"   решения: {decisions}")
        print(f"   правила: {dict(incident_rules[kind])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

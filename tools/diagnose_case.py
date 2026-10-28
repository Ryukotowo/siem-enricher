"""Диагностика одного типа случая: почему получен такой класс и такое решение."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402


def main() -> int:
    kinds = sys.argv[1:] or ["benign_upload_public", "ransomware_encrypt", "benign_read_internal"]
    setup_logging(level="ERROR", fmt="json")
    config = load_config(PROJECT_ROOT / "config/config.local.json")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)

    seen: set[str] = set()
    for line in (PROJECT_ROOT / "var/experiment/dataset.jsonl").read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        kind = raw.get("x_kind")
        if kind not in kinds or kind in seen:
            continue
        seen.add(kind)
        event = pipeline.normalize("experiment", raw)
        enriched = pipeline.enrich(event)
        result = enriched.enrichment
        document = enriched.document or {}
        print("=" * 92)
        print(f"случай: {kind} | метка: {raw.get('x_label')} | уровень правила: {raw['rule']['level']}")
        print(f"действие: {event.action.value if hasattr(event.action, 'value') else event.action}")
        for item in event.files:
            print(f"  файл: {item.path}")
        print(f"класс: {result.sensitivity.level.value} "
              f"(уверенность {result.sensitivity.confidence:.3f}, метод {result.sensitivity.method})")
        print(f"обоснование: {result.sensitivity.reason}")
        print(f"риск: {result.risk.score:.4f} / {result.risk.severity.value}")
        print(f"компоненты риска: {getattr(result.risk, 'components', '—')}")
        print(f"происхождение: глубина {result.provenance_depth}, "
              f"внешних адресатов {document.get('external_destinations_count')}")
        print(f"решение: {result.policy_decision.value}")
        for decision in result.policies:
            print(f"  правило {decision.rule_id} ({decision.severity.value}): {decision.title}")
            for action in getattr(decision, 'actions', []) or []:
                print(f"    действие: {action}")
        print(f"предупреждения: {result.warnings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

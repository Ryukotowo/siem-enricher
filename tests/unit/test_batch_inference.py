"""Тест: пакетное обогащение совпадает с поштучным."""

from __future__ import annotations

import unittest

from siem_enricher.config import AppConfig, load_structured
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.metrics import reset_metrics, service_metrics
from tests import PROJECT_ROOT

PATHS = [
    r"C:\HR\Зарплатная_ведомость_2025.xlsx",
    r"C:\Public\пресс-релиз.docx",
    r"C:\Секреты\пароли.txt",
    r"C:\Документы\Служебная_записка.docx",
]


def build_pipeline() -> EnrichmentPipeline:
    data = load_structured(PROJECT_ROOT / "config" / "config.local.json")
    data["ml"]["type"] = "heuristic"
    data["ml"]["labels_file"] = str(PROJECT_ROOT / "config" / "sensitivity_labels.json")
    data["ml"]["artifact_path"] = str(PROJECT_ROOT / "ml" / "artifacts" / "sensitivity_transformer")
    data["provenance"] = {"backend": "memory"}
    config = AppConfig.from_dict(data, base_dir=PROJECT_ROOT,
                                 path=PROJECT_ROOT / "config" / "config.local.json")
    reset_metrics()
    return EnrichmentPipeline.from_config(config, in_memory_store=True, metrics=service_metrics())


def documents(pipeline: EnrichmentPipeline, paths: list[str]) -> list:
    return [
        pipeline.normalize("test", {
            "event_id": f"e{index}", "ts": "2026-11-13T10:00:00Z", "action": "read",
            "user": "ivanov", "host": "ws-1", "path": path,
        })
        for index, path in enumerate(paths)
    ]


class BatchInferenceTest(unittest.TestCase):
    def test_batch_matches_single(self) -> None:
        pipeline = build_pipeline()
        try:
            events = documents(pipeline, PATHS)
            single = [pipeline.enrich(event) for event in events]
            batch = pipeline.enrich_batch(events)
        finally:
            pipeline.close()

        self.assertEqual(len(single), len(batch))
        for left, right in zip(single, batch):
            self.assertEqual(left.event.event_id, right.event.event_id)
            self.assertEqual(left.enrichment.sensitivity.level, right.enrichment.sensitivity.level)
            self.assertEqual(left.enrichment.policy_decision, right.enrichment.policy_decision)
            self.assertAlmostEqual(left.enrichment.risk.score, right.enrichment.risk.score, places=6)

    def test_empty_batch(self) -> None:
        pipeline = build_pipeline()
        try:
            self.assertEqual(pipeline.enrich_batch([]), [])
        finally:
            pipeline.close()


if __name__ == "__main__":
    unittest.main()

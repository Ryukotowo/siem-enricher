"""Сквозные тесты конвейера обогащения: генерация событий -> обогащение -> проверка."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.generate_sample_events import build_events

from siem_enricher.config import AppConfig, MlConfig, load_structured
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.metrics import reset_metrics, service_metrics
from tests import PROJECT_ROOT

CHECKPOINT = PROJECT_ROOT / "ml" / "artifacts" / "sensitivity_transformer"
HAS_TORCH = (
    importlib.util.find_spec("torch") is not None
    and importlib.util.find_spec("transformers") is not None
)


def build_config_dict(root: Path, ml_type: str = "heuristic") -> dict[str, Any]:
    """Конфигурация для тестов: память вместо БД, файл вместо Kafka, локальные правила."""
    data = load_structured(PROJECT_ROOT / "config" / "config.local.json")
    data["ml"]["type"] = ml_type
    # Пути к общим файлам проекта — абсолютные: конфигурация теста лежит вне каталога config/
    data["ml"]["labels_file"] = str(PROJECT_ROOT / "config" / "sensitivity_labels.json")
    data["ml"]["artifact_path"] = str(CHECKPOINT)
    data["provenance"] = {"backend": "memory"}
    data["sink"] = {
        "type": "file_jsonl",
        "options": {"path": str(root / "enriched.jsonl"), "mode": "overwrite"},
    }
    data["source"] = {"type": "file_replay", "options": {"path": str(root / "input.jsonl")}}
    data["policy"]["file"] = str(PROJECT_ROOT / "config" / "policies.json")
    data["policy"]["audit_log"] = str(root / "audit.jsonl")
    return data


def build_test_config(root: Path, ml_type: str = "heuristic") -> AppConfig:
    config = AppConfig.from_dict(
        build_config_dict(root, ml_type),
        base_dir=PROJECT_ROOT,
        path=PROJECT_ROOT / "config" / "config.local.json",
    )
    errors = config.validate()
    assert not errors, errors
    return config


class PipelineEndToEndTest(unittest.TestCase):
    """Конвейер целиком на синтетическом потоке событий (без внешних сервисов)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        reset_metrics()
        cls.metrics = service_metrics()
        cls.config = build_test_config(cls.root)
        cls.pipeline = EnrichmentPipeline.from_config(cls.config, metrics=cls.metrics, in_memory_store=True)
        cls.results = []
        for document in build_events(scenario="mixed", seed=7):
            _, enriched, siem_document = cls.pipeline.enrich_document("file_replay", document)
            cls.results.append((enriched, siem_document))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pipeline.close()
        cls._tmp.cleanup()

    # --- вспомогательные методы ---
    def by_tag(self, tag: str) -> list[tuple[Any, dict]]:
        return [(e, d) for e, d in self.results if str(e.event.raw.get("x_scenario")) == tag]

    def rules_of(self, enriched) -> list[str]:
        return [outcome.rule_id for outcome in enriched.enrichment.policies]

    # --- проверки ---
    def test_all_events_are_enriched(self) -> None:
        self.assertGreaterEqual(len(self.results), 10)
        for _enriched, document in self.results:
            self.assertIsNotNone(document.get("data_sensitivity"))
            self.assertIn("risk_score", document)
            self.assertIn("provenance_chain", document)
            self.assertIn("action", document)
            self.assertTrue(document["enrichment"]["enricher_version"])

    def test_secret_objects_are_detected(self) -> None:
        secret_events = [e for e, _ in self.results if e.enrichment.sensitivity.level.value == "secret"]
        self.assertTrue(secret_events)
        self.assertTrue(all(e.enrichment.risk.severity.value in {"high", "critical"} for e in secret_events))

    def test_public_objects_are_detected(self) -> None:
        public_events = [e for e, _ in self.by_tag("benign_public")]
        self.assertTrue(public_events)
        for enriched in public_events:
            self.assertEqual(enriched.enrichment.sensitivity.level.value, "public")
            self.assertEqual(enriched.enrichment.policy_decision.value, "tag")

    def test_confidential_hr_documents(self) -> None:
        for tag in ("insider_read", "insider_hr"):
            for enriched, _ in self.by_tag(tag):
                self.assertEqual(enriched.enrichment.sensitivity.level.value, "confidential")

    def test_exfiltration_rule_and_masking(self) -> None:
        uploads = self.by_tag("exfil_upload")
        self.assertTrue(uploads)
        for enriched, document in uploads:
            self.assertIn("POL-001", self.rules_of(enriched))
            self.assertIn(enriched.enrichment.risk.severity.value, {"high", "critical"})
            self.assertIn("dlp:exfiltration", document.get("tags", []))
            self.assertTrue(document["enrichment"]["masked_fields"])
            self.assertTrue(document["files"][0]["path"].startswith("sha256:"))

    def test_usb_copy_rule(self) -> None:
        for enriched, _ in self.by_tag("usb_copy"):
            self.assertTrue({"POL-006", "POL-011"} & set(self.rules_of(enriched)))

    def test_ransomware_rule(self) -> None:
        for enriched, _ in self.by_tag("ransomware"):
            # шифрование защищаемых данных блокируется правилом POL-010 (при stop_on_block
            # остальные правила не проверяются), переименование фиксируется правилом POL-007
            rules = self.rules_of(enriched)
            self.assertTrue({"POL-007", "POL-010"} & set(rules), rules)
        blocks = [enriched for enriched, _ in self.by_tag("ransomware")
                  if enriched.event.action.value == "encrypt"]
        self.assertTrue(blocks, "в наборе нет события шифрования")
        for enriched in blocks:
            self.assertIn("POL-010", self.rules_of(enriched))
            self.assertEqual(enriched.enrichment.policy_decision.value, "block")

    def test_mass_access_rule(self) -> None:
        for enriched, _ in self.by_tag("mass_copy"):
            self.assertTrue({"POL-003", "POL-012"} & set(self.rules_of(enriched)))
            self.assertGreaterEqual(len(enriched.event.files), 10)

    def test_secret_access_blocks_in_dry_run(self) -> None:
        for enriched, _ in self.by_tag("secret_access"):
            self.assertIn("POL-002", self.rules_of(enriched))
            self.assertEqual(enriched.enrichment.policy_decision.value, "block")
            statuses = [
                action.status.value
                for outcome in enriched.enrichment.policies
                for action in outcome.actions
                if action.type.value == "block"
            ]
            self.assertEqual(set(statuses), {"simulated"})

    def test_provenance_accumulates_for_repeated_file(self) -> None:
        reference = self.by_tag("usb_copy")[0][0].event
        chain = self.pipeline.chain(r"C:\HR\Зарплатная_ведомость_2025.xlsx", reference)
        self.assertGreaterEqual(chain.depth, 2)
        self.assertIn("copy", [step.action.value for step in chain.steps])

    def test_policies_can_be_disabled(self) -> None:
        upload = next(
            event for event in build_events(scenario="mixed", seed=7)
            if event.get("x_scenario") == "exfil_upload"
        )
        _, _, with_policies = self.pipeline.enrich_document("file_replay", upload, apply_policies=True)
        _, enriched_off, without_policies = self.pipeline.enrich_document(
            "file_replay", upload, apply_policies=False
        )
        # Правила по-прежнему проверяются (режим анализа), но действия не выполняются
        self.assertIn("POL-001", with_policies.get("policy_rule_ids"))
        self.assertIn("POL-001", without_policies.get("policy_rule_ids"))
        self.assertTrue(with_policies["enrichment"]["masked_fields"])
        self.assertFalse(without_policies["enrichment"]["masked_fields"])
        self.assertTrue(
            all(not outcome.actions for outcome in enriched_off.enrichment.policies),
            "в режиме без применения политик действия не выполняются",
        )

    def test_metrics_are_collected(self) -> None:
        self.assertGreaterEqual(self.metrics.events_enriched.total(), len(self.results))
        self.assertGreaterEqual(self.metrics.enrichment_duration.count(), len(self.results))
        self.assertGreater(self.metrics.policy_triggered.total(), 0)
        self.assertGreater(self.metrics.classified.total(), 0)

    def test_summary_statistics(self) -> None:
        summary = self.pipeline.summarize([e for e, _ in self.results])
        self.assertEqual(summary["events"], len(self.results))
        self.assertGreater(summary["mean_risk_score"], 0.0)
        self.assertIn("POL-001", summary["triggered_rules"])

    def test_pipeline_describe(self) -> None:
        info = self.pipeline.describe()
        self.assertEqual(info["classifier"]["method"], "heuristic")
        self.assertEqual(info["provenance"]["backend"], "memory")
        self.assertGreater(info["policies"], 0)


@unittest.skipUnless(HAS_TORCH and CHECKPOINT.exists(), "нет torch/transformers или чекпоинта модели")
class TransformerClassifierTest(unittest.TestCase):
    """Проверка загрузки дообученной модели и гибридной схемы (выполняется при наличии torch)."""

    @classmethod
    def setUpClass(cls) -> None:
        from siem_enricher.ml import build_classifier

        cls.labels = PROJECT_ROOT / "config" / "sensitivity_labels.json"
        cls.classifier = build_classifier(
            MlConfig(
                type="hybrid",
                artifact_path=str(CHECKPOINT),
                labels_file=str(cls.labels),
                device="cpu",
            ),
            labels_path=cls.labels,
        )

    def test_describe_reports_model_and_categories(self) -> None:
        info = self.classifier.describe()
        self.assertEqual(info["method"], "hybrid")
        self.assertIn("BertForSequenceClassification", info["algorithm"])
        for category in ("personal", "banking", "commercial", "ip", "official_internal", "public"):
            self.assertIn(category, info["categories"])

    def test_classification_of_typical_objects(self) -> None:
        cases = {
            r"C:\keys\id_rsa": "secret",
            r"C:\secrets\.env": "secret",
            r"C:\HR\Зарплатная_ведомость_2025.xlsx": "confidential",
            r"C:\Бухгалтерия\Счет_фактура_№1420.docx": "confidential",
            r"C:\Public\readme.md": "public",
            r"C:\Public\Шаблон_письма_клиенту.docx": "public",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(self.classifier.predict(path).level.value, expected)

    def test_search_assessment_explains_decision(self) -> None:
        assessment = self.classifier.predict(r"C:\HR\Зарплатная_ведомость_2025.xlsx")
        self.assertGreater(assessment.confidence, 0.5)
        self.assertTrue(assessment.reason)
        self.assertTrue(assessment.evidence)


if __name__ == "__main__":
    unittest.main()

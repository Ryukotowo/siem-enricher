"""Тесты гибридной схемы: ML-модель по имени + правила по каталогу и расширению."""

from __future__ import annotations

import unittest
from typing import Iterable

from siem_enricher.ml import HeuristicSensitivityClassifier
from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.ml.hybrid import HybridSettings, HybridSensitivityClassifier
from siem_enricher.models.enums import SensitivityLevel
from siem_enricher.models.enrichment import SensitivityAssessment


class FakeModel(SensitivityClassifier):
    """Заглушка ML-модели с фиксированным прогнозом — для проверки логики объединения."""

    method = "fake-model"

    def __init__(self, level: SensitivityLevel, confidence: float) -> None:
        self.level = level
        self.confidence = confidence
        self.model_version = "fake-1.0"

    def predict(self, path: str) -> SensitivityAssessment:
        return SensitivityAssessment(
            target=path,
            level=self.level,
            confidence=self.confidence,
            method=self.method,
            model_version=self.model_version,
            reason="заглушка модели",
            scores={"fake-category": self.confidence},
        )

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        return [self.predict(path) for path in paths]


def build_hybrid(
    level: SensitivityLevel,
    confidence: float,
    settings: HybridSettings | None = None,
) -> HybridSensitivityClassifier:
    return HybridSensitivityClassifier(
        primary=FakeModel(level, confidence),
        rules=HeuristicSensitivityClassifier(),
        settings=settings or HybridSettings(),
    )


class HybridClassifierTest(unittest.TestCase):
    def test_policy_signal_overrides_confident_model(self) -> None:
        """Файл в общедоступном каталоге остаётся public, даже если модель уверена в обратном."""
        classifier = build_hybrid(SensitivityLevel.CONFIDENTIAL, 0.95)
        assessment = classifier.predict(r"C:\Public\Шаблон_письма_клиенту.docx")
        self.assertEqual(assessment.level, SensitivityLevel.PUBLIC)
        self.assertIn("признак размещения", assessment.reason)
        self.assertIn("понизил", assessment.reason)

    def test_rules_escalate_weak_model(self) -> None:
        classifier = build_hybrid(SensitivityLevel.INTERNAL, 0.40)
        assessment = classifier.predict(r"C:\HR\Зарплатная_ведомость_2025.xlsx")
        self.assertEqual(assessment.level, SensitivityLevel.CONFIDENTIAL)
        self.assertGreater(assessment.confidence, 0.40)
        self.assertEqual(assessment.method, "hybrid")

    def test_credentials_escalate_to_secret(self) -> None:
        classifier = build_hybrid(SensitivityLevel.PUBLIC, 0.90)
        assessment = classifier.predict(r"C:\keys\id_rsa")
        self.assertEqual(assessment.level, SensitivityLevel.SECRET)

    def test_no_downgrade_of_confident_model_when_override_disabled(self) -> None:
        settings = HybridSettings(policy_override=False, allow_downgrade=True)
        classifier = build_hybrid(SensitivityLevel.CONFIDENTIAL, 0.95, settings)
        assessment = classifier.predict(r"C:\Public\readme.md")
        self.assertEqual(assessment.level, SensitivityLevel.CONFIDENTIAL)

    def test_downgrade_of_uncertain_model_when_override_disabled(self) -> None:
        settings = HybridSettings(policy_override=False, allow_downgrade=True)
        classifier = build_hybrid(SensitivityLevel.CONFIDENTIAL, 0.57, settings)
        assessment = classifier.predict(r"C:\Public\readme.md")
        self.assertEqual(assessment.level, SensitivityLevel.PUBLIC)

    def test_no_downgrade_when_disabled_completely(self) -> None:
        settings = HybridSettings(policy_override=False, allow_downgrade=False)
        classifier = build_hybrid(SensitivityLevel.CONFIDENTIAL, 0.57, settings)
        self.assertEqual(classifier.predict(r"C:\Public\readme.md").level, SensitivityLevel.CONFIDENTIAL)

    def test_agreement_blends_confidence(self) -> None:
        classifier = build_hybrid(SensitivityLevel.CONFIDENTIAL, 0.90)
        assessment = classifier.predict(r"C:\HR\Зарплатная_ведомость_2025.xlsx")
        self.assertEqual(assessment.level, SensitivityLevel.CONFIDENTIAL)
        self.assertLess(assessment.confidence, 0.90)
        self.assertGreater(assessment.confidence, 0.50)

    def test_model_keeps_high_class_without_rule_support(self) -> None:
        classifier = build_hybrid(SensitivityLevel.SECRET, 0.80)
        assessment = classifier.predict(r"X:\data\файл.bin")
        self.assertEqual(assessment.level, SensitivityLevel.SECRET)

    def test_reason_contains_both_signals(self) -> None:
        classifier = build_hybrid(SensitivityLevel.INTERNAL, 0.40)
        assessment = classifier.predict(r"C:\HR\Зарплатная_ведомость_2025.xlsx")
        self.assertIn("ML:", assessment.reason)
        self.assertIn("правила:", assessment.reason)
        self.assertTrue(assessment.evidence)

    def test_describe_contains_rules_and_artifact(self) -> None:
        info = build_hybrid(SensitivityLevel.INTERNAL, 0.5).describe()
        self.assertEqual(info["method"], "hybrid")
        self.assertEqual(info["rules"], "heuristic")
        self.assertIn("policy_override", info)


if __name__ == "__main__":
    unittest.main()

"""Тесты оценки риска события."""

from __future__ import annotations

import unittest

from siem_enricher.config import RiskConfig
from siem_enricher.enricher.risk import RiskScorer, RiskWeights, combine_scores
from siem_enricher.models import (
    FileRef,
    NormalizedEvent,
    ProvenanceAction,
    RemoteEndpoint,
    SensitivityAssessment,
    SensitivityLevel,
    Severity,
    UserInfo,
    utcnow,
)


def make_event(
    action: ProvenanceAction,
    files: int = 1,
    remote: RemoteEndpoint | None = None,
    privileged: bool = False,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-1",
        timestamp=utcnow(),
        source="test",
        action=action,
        user=UserInfo(name="ivanov", is_privileged=privileged),
        files=[FileRef(path=rf"C:\HR\Документ_{index}.xlsx") for index in range(files)],
        remote=remote,
    )


def assessment(level: SensitivityLevel, confidence: float = 0.9) -> SensitivityAssessment:
    return SensitivityAssessment(target="x", level=level, confidence=confidence, method="test")


class RiskScorerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scorer = RiskScorer.from_config(RiskConfig())

    def test_score_grows_with_danger(self) -> None:
        public_read = self.scorer.score(
            make_event(ProvenanceAction.READ), assessment(SensitivityLevel.PUBLIC, 0.6)
        )
        confidential_copy = self.scorer.score(
            make_event(ProvenanceAction.COPY), assessment(SensitivityLevel.CONFIDENTIAL, 0.8)
        )
        confidential_upload = self.scorer.score(
            make_event(ProvenanceAction.UPLOAD, remote=RemoteEndpoint(ip="185.220.101.5", is_external=True)),
            assessment(SensitivityLevel.CONFIDENTIAL, 0.8),
        )
        self.assertLess(public_read.score, confidential_copy.score)
        self.assertLess(confidential_copy.score, confidential_upload.score)

    def test_severity_levels(self) -> None:
        low = self.scorer.score(make_event(ProvenanceAction.READ), assessment(SensitivityLevel.PUBLIC, 0.6))
        critical = self.scorer.score(
            make_event(ProvenanceAction.UPLOAD, remote=RemoteEndpoint(ip="185.220.101.5", is_external=True)),
            assessment(SensitivityLevel.SECRET, 0.95),
        )
        self.assertEqual(low.severity, Severity.LOW)
        self.assertIn(critical.severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertGreater(critical.score, low.score)

    def test_private_address_does_not_increase_risk(self) -> None:
        private = self.scorer.score(
            make_event(ProvenanceAction.COPY, remote=RemoteEndpoint(ip="10.0.0.11", is_external=False)),
            assessment(SensitivityLevel.CONFIDENTIAL, 0.8),
        )
        self.assertEqual(private.components["external_destination"], 0.0)

        external = self.scorer.score(
            make_event(ProvenanceAction.COPY, remote=RemoteEndpoint(ip="185.220.101.5", is_external=True)),
            assessment(SensitivityLevel.CONFIDENTIAL, 0.8),
        )
        self.assertGreater(external.components["external_destination"], 0.0)
        self.assertGreater(external.score, private.score)

    def test_volume_increases_risk(self) -> None:
        single = self.scorer.score(make_event(ProvenanceAction.COPY, files=1), assessment(SensitivityLevel.CONFIDENTIAL))
        many = self.scorer.score(make_event(ProvenanceAction.COPY, files=20), assessment(SensitivityLevel.CONFIDENTIAL))
        self.assertGreater(many.score, single.score)
        self.assertGreater(many.components["volume"], single.components["volume"])

    def test_privileged_user_adds_component(self) -> None:
        ordinary = self.scorer.score(make_event(ProvenanceAction.READ), assessment(SensitivityLevel.CONFIDENTIAL))
        privileged = self.scorer.score(
            make_event(ProvenanceAction.READ, privileged=True), assessment(SensitivityLevel.CONFIDENTIAL)
        )
        self.assertEqual(ordinary.components["privileged_user"], 0.0)
        self.assertGreater(privileged.components["privileged_user"], 0.0)
        self.assertGreater(privileged.score, ordinary.score)

    def test_confidence_affects_score(self) -> None:
        sure = self.scorer.score(make_event(ProvenanceAction.READ), assessment(SensitivityLevel.INTERNAL, 0.95))
        unsure = self.scorer.score(make_event(ProvenanceAction.READ), assessment(SensitivityLevel.INTERNAL, 0.35))
        self.assertGreater(sure.score, unsure.score)

    def test_score_is_bounded_and_explained(self) -> None:
        result = self.scorer.score(
            make_event(ProvenanceAction.UPLOAD, files=40, remote=RemoteEndpoint(ip="185.220.101.5", is_external=True), privileged=True),
            assessment(SensitivityLevel.SECRET, 0.99),
        )
        self.assertLessEqual(result.score, 1.0)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertTrue(result.explanation)
        self.assertIn("secret", " ".join(result.explanation))
        self.assertGreater(result.components["amplifier"], 1.0)

    def test_custom_weights_are_used(self) -> None:
        scorer = RiskScorer.from_config(RiskConfig(weights={"sensitivity": 0.9, "confidence": 0.0,
                                                           "action": 0.0, "external_destination": 0.0,
                                                           "privileged_user": 0.0, "volume": 0.0}))
        result = scorer.score(make_event(ProvenanceAction.READ), assessment(SensitivityLevel.CONFIDENTIAL, 0.5))
        self.assertAlmostEqual(result.components["confidence"], 0.0)
        self.assertGreater(result.components["sensitivity"], 0.5)

    def test_describe_reports_configuration(self) -> None:
        info = self.scorer.describe()
        self.assertIn("thresholds", info)
        self.assertIn("weights", info)

    def test_weights_dataclass_round_trip(self) -> None:
        self.assertAlmostEqual(sum(RiskWeights().as_dict().values()), 1.0)
        weights = RiskWeights.from_mapping({"sensitivity": 0.5})
        self.assertEqual(weights.sensitivity, 0.5)
        self.assertEqual(weights.action, RiskWeights().action)

    def test_combine_scores(self) -> None:
        self.assertEqual(combine_scores([0.1, 0.7, 0.3]), 0.7)
        self.assertAlmostEqual(combine_scores([0.2, 0.4], mode="mean"), 0.3)
        with self.assertRaises(ValueError):
            combine_scores([0.1], mode="unknown")


if __name__ == "__main__":
    unittest.main()

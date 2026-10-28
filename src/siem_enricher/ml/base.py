"""Интерфейс классификатора конфиденциальности."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Sequence

from siem_enricher.models.enrichment import SensitivityAssessment


class SensitivityClassifier(ABC):
    """Базовый интерфейс классификатора: путь файла -> класс конфиденциальности."""

    method: str = "unknown"
    model_version: str = "unknown"

    @abstractmethod
    def predict(self, path: str) -> SensitivityAssessment:
        """Определить класс конфиденциальности одного объекта."""

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        """Определить класс для набора объектов (по умолчанию — последовательно)."""
        return [self.predict(path) for path in paths]

    def describe(self) -> dict[str, str]:
        return {"method": self.method, "model_version": self.model_version}


def aggregate_level(assessments: Sequence[SensitivityAssessment]) -> SensitivityAssessment:
    """Свернуть оценки нескольких файлов в одну для события."""
    if not assessments:
        raise ValueError("Нет оценок для агрегации")
    best = max(assessments, key=lambda a: (a.level.rank, a.confidence))
    if len(assessments) == 1:
        return best
    return SensitivityAssessment(
        target=best.target,
        level=best.level,
        confidence=best.confidence,
        method=best.method,
        model_version=best.model_version,
        reason=f"наиболее чувствительный объект из {len(assessments)}: {best.reason}",
        evidence=list(best.evidence),
        scores=dict(best.scores),
    )

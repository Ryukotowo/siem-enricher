"""Тесты кэша классификации по имени файла."""

from __future__ import annotations

import unittest

from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.ml.cache import CachingClassifier
from siem_enricher.models.enrichment import SensitivityAssessment, SensitivityLevel


class CountingClassifier(SensitivityClassifier):
    """Классификатор-заглушка, считающий обращения к модели."""

    method = "counting"
    model_version = "test-1"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths):
        batch = [str(path) for path in paths]
        self.calls.append(batch)
        return [
            SensitivityAssessment(
                target=path,
                level=SensitivityLevel.SECRET if "secret" in path else SensitivityLevel.PUBLIC,
                confidence=0.9,
                method=self.method,
                model_version=self.model_version,
            )
            for path in batch
        ]


class CachingClassifierTest(unittest.TestCase):
    def test_repeated_path_is_not_recomputed(self) -> None:
        inner = CountingClassifier()
        cached = CachingClassifier(inner, max_entries=100)
        for _ in range(5):
            cached.predict(r"C:\отчёт.docx")
        self.assertEqual(len(inner.calls), 1)
        self.assertEqual(cached.hits, 4)
        self.assertEqual(cached.misses, 1)

    def test_case_and_spaces_are_normalised(self) -> None:
        inner = CountingClassifier()
        cached = CachingClassifier(inner, max_entries=100)
        cached.predict(r"C:\Отчёт.docx")
        cached.predict(r"  c:\отчёт.docx ")
        self.assertEqual(len(inner.calls), 1)

    def test_batch_mixed_hits_and_misses(self) -> None:
        inner = CountingClassifier()
        cached = CachingClassifier(inner, max_entries=100)
        cached.predict_many([r"C:\a.docx", r"C:\b.docx"])
        result = cached.predict_many([r"C:\a.docx", r"C:\c.docx"])
        self.assertEqual(len(result), 2)
        self.assertEqual(len(inner.calls), 2)
        self.assertEqual(inner.calls[1], [r"C:\c.docx"])

    def test_lru_eviction_keeps_size_bounded(self) -> None:
        inner = CountingClassifier()
        cached = CachingClassifier(inner, max_entries=2)
        for name in ("a", "b", "c"):
            cached.predict(rf"C:\{name}.docx")
        cached.predict(r"C:\a.docx")
        self.assertEqual(len(inner.calls), 4)
        self.assertEqual(len(cached._cache), 2)

    def test_describe_reports_statistics(self) -> None:
        inner = CountingClassifier()
        cached = CachingClassifier(inner, max_entries=10)
        cached.predict(r"C:\a.docx")
        info = cached.describe()
        self.assertEqual(info["method"], "counting")
        self.assertTrue(info["cache"]["enabled"])
        self.assertEqual(info["cache"]["misses"], 1)


if __name__ == "__main__":
    unittest.main()

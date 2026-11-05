"""Кэш классификации по пути: повторные имена не пересчитываются моделью."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Iterable

from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.models.enrichment import SensitivityAssessment


class CachingClassifier(SensitivityClassifier):
    """Обёртка над классификатором с кэшем последних результатов по пути.

    В потоке одни и те же файлы встречаются многократно, поэтому повторный вызов
    модели для того же пути бессмыслен: результат зависит только от имени.
    """

    def __init__(self, inner: SensitivityClassifier, max_entries: int = 4096) -> None:
        self.inner = inner
        self.max_entries = max(1, int(max_entries))
        self._cache: OrderedDict[str, SensitivityAssessment] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @property
    def method(self) -> str:
        return self.inner.method

    @property
    def model_version(self) -> str:
        return self.inner.model_version

    @staticmethod
    def _key(path: str) -> str:
        return str(path).strip().lower()

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        path_list = [str(path) for path in paths]
        if not path_list:
            return []

        results: list[SensitivityAssessment | None] = [None] * len(path_list)
        missing: list[int] = []
        for index, path in enumerate(path_list):
            key = self._key(path)
            cached = self._cache.get(key)
            if cached is None:
                missing.append(index)
            else:
                self._cache.move_to_end(key)
                self.hits += 1
                results[index] = cached

        if missing:
            computed = self.inner.predict_many([path_list[index] for index in missing])
            for index, assessment in zip(missing, computed):
                key = self._key(path_list[index])
                self._cache[key] = assessment
                self._cache.move_to_end(key)
                while len(self._cache) > self.max_entries:
                    self._cache.popitem(last=False)
                results[index] = assessment
            self.misses += len(missing)

        return [item for item in results if item is not None]

    def describe(self) -> dict[str, Any]:
        info = dict(self.inner.describe())
        info["cache"] = {
            "enabled": True,
            "max_entries": self.max_entries,
            "entries": len(self._cache),
            "hits": self.hits,
            "misses": self.misses,
        }
        return info

    def clear(self) -> None:
        self._cache.clear()


__all__ = ["CachingClassifier"]

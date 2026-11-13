"""Батчевый инференс: классификация пачкой событий, остальное по порядку."""

from __future__ import annotations

import ast
from pathlib import Path

PIPELINE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "enricher" / "pipeline.py"

OLD_HEAD = '''    def enrich(self, event: NormalizedEvent, apply_policies: bool = True) -> EnrichedEvent:
        """Обогатить нормализованное событие."""
        started = time.perf_counter()
        warnings: list[str] = []

        with event_context(event.event_id):
            # 1. Классификация конфиденциальности для каждого файла
            per_file: list[SensitivityAssessment] = []
            if event.files:'''

NEW_HEAD = '''    def enrich(self, event: NormalizedEvent, apply_policies: bool = True) -> EnrichedEvent:
        """Обогатить нормализованное событие."""
        per_file = self._classify_event(event)
        return self._assemble(event, per_file, apply_policies=apply_policies)

    def enrich_batch(self, events: Sequence[NormalizedEvent],
                     apply_policies: bool = True) -> list[EnrichedEvent]:
        """Обогатить пачку событий, классифицируя имена одним батчем.

        Классификатор получает все имена пачки сразу — это главный выигрыш;
        происхождение, риск и политики считаются по одному событию в исходном
        порядке, поэтому цепочки не перемешиваются.
        """
        if not events:
            return []
        targets: list[str] = []
        spans: list[tuple[int, int]] = []
        for event in events:
            paths = [f.path for f in event.files]
            spans.append((len(targets), len(targets) + len(paths)))
            targets.extend(paths)

        assessments: list[SensitivityAssessment] = []
        if targets:
            try:
                assessments = list(self.classifier.predict_many(targets))
            except Exception as exc:  # noqa: BLE001 - падение классификатора не теряет события
                logger.error("Ошибка пакетной классификации", extra={"reason": str(exc)})
                assessments = []

        results: list[EnrichedEvent] = []
        for event, (start, end) in zip(events, spans):
            chunk = assessments[start:end] if len(assessments) >= end else []
            results.append(self._assemble(event, chunk, apply_policies=apply_policies))
        return results

    def _classify_event(self, event: NormalizedEvent) -> list[SensitivityAssessment]:
        """Классифицировать файлы одного события."""
        with event_context(event.event_id):
            per_file: list[SensitivityAssessment] = []
            if event.files:'''

OLD_MID = '''            else:
                warnings.append("в событии не обнаружено файлов-объектов: классификация не выполнялась")

            for assessment in per_file:
                self.metrics.classified.inc({"level": assessment.level.value, "method": assessment.method})
'''

NEW_MID = '''            else:
                per_file = []
            return per_file

    def _assemble(
        self,
        event: NormalizedEvent,
        per_file: Sequence[SensitivityAssessment],
        apply_policies: bool = True,
    ) -> EnrichedEvent:
        """Собрать результат обогащения по готовым оценкам классификатора."""
        started = time.perf_counter()
        warnings: list[str] = []
        sensitivity = self._aggregate(per_file) if per_file else self._no_files_assessment()
        if not event.files:
            warnings.append("в событии не обнаружено файлов-объектов: классификация не выполнялась")

        for assessment in per_file:
            self.metrics.classified.inc({"level": assessment.level.value, "method": assessment.method})
'''


def main() -> int:
    text = PIPELINE.read_text(encoding="utf-8")
    if "def enrich_batch" in text:
        print("батчевый метод уже есть")
        return 0
    if OLD_HEAD not in text or OLD_MID not in text:
        print("!! не найдены ожидаемые блоки enrich")
        return 1
    text = text.replace(OLD_HEAD, NEW_HEAD, 1)
    text = text.replace(OLD_MID, NEW_MID, 1)
    if "from collections.abc import" in text and "Sequence" not in text:
        text = text.replace("from collections.abc import Iterable",
                            "from collections.abc import Iterable, Sequence", 1)
    PIPELINE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("pipeline: enrich_batch и _assemble")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

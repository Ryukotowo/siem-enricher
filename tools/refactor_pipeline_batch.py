"""Переписать enrich: выделить _classify_event и _assemble, добавить enrich_batch."""

from __future__ import annotations

import ast
from pathlib import Path

PIPELINE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "enricher" / "pipeline.py"

HEADER = '''    def enrich(self, event: NormalizedEvent, apply_policies: bool = True) -> EnrichedEvent:
        """Обогатить нормализованное событие."""
        per_file = self._classify_event(event)
        return self._assemble(event, per_file, apply_policies=apply_policies)

    def enrich_batch(self, events: Sequence[NormalizedEvent],
                     apply_policies: bool = True) -> list[EnrichedEvent]:
        """Обогатить пачку событий, классифицируя имена одним батчем.

        Классификатор получает имена всей пачки сразу — это основной выигрыш;
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
            if not event.files:
                return per_file
            # объект на съёмном носителе не характеризует защищаемый объект:
            # классифицируем исходный путь, если он есть
            from siem_enricher.extractor.patterns import is_removable_path

            targets = [f.path for f in event.files if not is_removable_path(f.path)]
            try:
                per_file = list(self.classifier.predict_many(targets or [f.path for f in event.files]))
            except Exception as exc:  # noqa: BLE001 - сбой классификатора не теряет событие
                logger.error("Ошибка классификации конфиденциальности", extra={"reason": str(exc)})
                self.metrics.ml_fallback.inc({"reason": "classification_error"})
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
    lines = PIPELINE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("    def enrich("))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("    def enrich_document("))
    body = lines[start:end]
    marker = next(i for i, line in enumerate(body) if line.strip().startswith("# 2. Цепочки происхождения"))
    tail = []
    for line in body[marker:]:
        tail.append(line[4:] if line.startswith("            ") else line)

    new_text = "\n".join(HEADER.rstrip("\n").split("\n") + tail)
    result = lines[:start] + new_text.split("\n") + lines[end:]
    text = "\n".join(result) + "\n"
    if "Sequence" not in text.split("class ")[0]:
        text = text.replace("from collections.abc import Iterable",
                            "from collections.abc import Iterable, Sequence", 1)
    PIPELINE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("pipeline: enrich, enrich_batch, _classify_event, _assemble")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Батчевый инференс: имена из пачки событий классифицируются за один проход."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "src" / "siem_enricher" / "enricher" / "pipeline.py"
RUNTIME = ROOT / "src" / "siem_enricher" / "service" / "runtime.py"

WARM = '''    def warm(self, paths: Iterable[str]) -> None:
        """Предварительно классифицировать набор путей одним проходом модели."""
        prepared = [str(path) for path in paths if path]
        if not prepared:
            return
        warm_many = getattr(self.classifier, "predict_many", None)
        if warm_many is None:
            return
        try:
            warm_many(prepared)
        except Exception as exc:  # noqa: BLE001 - прогрев не должен ломать обработку
            logger.warning("Прогрев классификатора не удался", extra={"reason": str(exc)})

    def classify(self, path: str) -> SensitivityAssessment:'''

RUNTIME_OLD = '''            async for event in source.stream():
                enriched = self.pipeline.enrich(event, apply_policies=apply_policies)
                document = enriched.siem_document()
                if sink is not None and not await sink.send(document):
                    self.failed += 1
                else:
                    self.processed += 1
                if len(collected) < summary_limit:
                    collected.append(enriched)
                    if collect_documents:
                        documents.append(document)
                if limit and self.processed >= limit:
                    break'''

RUNTIME_NEW = '''            async def process_batch(items: list[Any]) -> None:
                paths: list[str] = []
                for item in items:
                    for file_item in (item.files or []):
                        path = getattr(file_item, "path", None)
                        if path:
                            paths.append(str(path))
                if paths:
                    self.pipeline.warm(paths)
                for item in items:
                    enriched = self.pipeline.enrich(item, apply_policies=apply_policies)
                    document = enriched.siem_document()
                    if sink is not None and not await sink.send(document):
                        self.failed += 1
                    else:
                        self.processed += 1
                    if len(collected) < summary_limit:
                        collected.append(enriched)
                        if collect_documents:
                            documents.append(document)

            batch: list[Any] = []
            batch_size = 16
            async for event in source.stream():
                batch.append(event)
                if len(batch) < batch_size:
                    continue
                await process_batch(batch)
                batch.clear()
                if limit and self.processed >= limit:
                    break
            if batch and not (limit and self.processed >= limit):
                await process_batch(batch)'''


def main() -> int:
    text = PIPELINE.read_text(encoding="utf-8")
    if "def warm(" not in text:
        if "    def classify(self, path: str) -> SensitivityAssessment:" not in text:
            print("!! не найден classify в конвейере")
            return 1
        text = text.replace("    def classify(self, path: str) -> SensitivityAssessment:", WARM, 1)
        PIPELINE.write_text(text, encoding="utf-8")
        ast.parse(text)
        print("конвейер: добавлен warm()")

    runtime = RUNTIME.read_text(encoding="utf-8")
    if "process_batch" in runtime:
        print("рантайм: уже обновлён")
        return 0
    if RUNTIME_OLD not in runtime:
        print("!! не найден цикл обработки")
        return 1
    runtime = runtime.replace(RUNTIME_OLD, RUNTIME_NEW, 1)
    if "from typing import Any" not in runtime:
        runtime = runtime.replace("from __future__ import annotations",
                                  "from __future__ import annotations\n\nfrom typing import Any", 1)
    RUNTIME.write_text(runtime, encoding="utf-8")
    ast.parse(runtime)
    print("рантайм: батчевая обработка по 16 событий")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

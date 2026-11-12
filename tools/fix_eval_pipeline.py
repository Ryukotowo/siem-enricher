"""Оценка моделей через конвейер: он знает карту классов."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

START = "def evaluate_direct(artifact: Path, rows: list[dict]) -> dict[str, float]:"
END_MARKER = "def finetune(train: list[dict], holdout: list[dict], artifact: Path) -> None:"

NEW_FUNC = '''def evaluate_model(artifact: Path, rows: list[dict]) -> dict[str, float]:
    """Оценить артефакт на отложенной выборке через сам конвейер.

    Конвейер умеет и карту категорий (базовая модель), и прямые классы
    (дообученная), поэтому сравнение корректно для обеих.
    """
    from siem_enricher.config import load_config
    from siem_enricher.enricher import EnrichmentPipeline

    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.artifact_path = str(artifact)
    config.ml.type = "transformer"
    config.ml.hybrid_enabled = False
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    try:
        pairs = [(row["level"], pipeline.classifier.predict(row["path"]).level.value) for row in rows]
    finally:
        pipeline.close()

    correct = sum(1 for truth, pred in pairs if truth == pred)
    positives = {"confidential", "secret"}
    tp = sum(1 for truth, pred in pairs if truth in positives and pred in positives)
    fn = sum(1 for truth, pred in pairs if truth in positives and pred not in positives)
    fp = sum(1 for truth, pred in pairs if truth not in positives and pred in positives)
    tn = sum(1 for truth, pred in pairs if truth not in positives and pred not in positives)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "по классам": round(correct / len(pairs), 3) if pairs else 0.0,
        "полнота": round(recall, 3),
        "точность": round(precision, 3),
        "F1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "объектов": len(pairs),
    }


'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if "def evaluate_model(" in text:
        print("оценка уже через конвейер")
        return 0
    if START not in text or END_MARKER not in text:
        print("!! не найдены границы функции оценки")
        return 1
    start = text.index(START)
    end = text.index(END_MARKER)
    text = text[:start] + NEW_FUNC + text[end:]
    text = text.replace("evaluate_direct(", "evaluate_model(")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("оценка переведена на конвейер")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

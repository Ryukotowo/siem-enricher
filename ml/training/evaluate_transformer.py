"""Оценка качества модели классификации конфиденциальности на отложенной выборке.

Скрипт считает метрики двух уровней:

1. **категории модели** (personal/commercial/... — то, чему обучена модель);
2. **классы конфиденциальности** (после отображения через ``config/sensitivity_labels.json``),
   именно они используются сервисом в правилах и риск-скоринге.

Пример::

    python ml/training/evaluate_transformer.py \
        --model ml/artifacts/sensitivity_transformer \
        --dataset ml/data/processed/files.csv \
        --output var/metrics_transformer.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from siem_enricher.config import MlConfig, load_structured  # noqa: E402
from siem_enricher.ml import build_classifier, load_category_map  # noqa: E402
from siem_enricher.models.enums import SensitivityLevel  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Оценка качества классификатора конфиденциальности")
    parser.add_argument("--model", default="ml/artifacts/sensitivity_transformer")
    parser.add_argument("--dataset", default="ml/data/processed/files.csv")
    parser.add_argument("--labels", default="config/sensitivity_labels.json")
    parser.add_argument("--path-column", default="path")
    parser.add_argument("--text-column", default="text")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--mode", choices=["transformer", "hybrid"], default="transformer",
                        help="transformer — оценивать чистую модель; hybrid — вместе с правилами")
    parser.add_argument("--group-column", default="source",
                        help="Колонка для разбивки метрик (например, source: csv/generator)")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--errors", type=int, default=10, help="Сколько ошибок показать")
    parser.add_argument("--output", default=None, help="Файл для сохранения метрик (JSON)")
    args = parser.parse_args(argv)

    try:
        import pandas as pd
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
    except ImportError as exc:  # pragma: no cover
        print(f"Не хватает зависимости: {exc}\nУстановите: pip install -r requirements-ml.txt", file=sys.stderr)
        return 2

    def resolve(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else PROJECT_ROOT / path

    model_path, dataset_path, labels_path = resolve(args.model), resolve(args.dataset), resolve(args.labels)
    if not dataset_path.exists():
        print(f"Датасет не найден: {dataset_path}", file=sys.stderr)
        return 1

    # utf-8-sig: поддержка CSV, выгруженных pandas с BOM
    frame = pd.read_csv(dataset_path, encoding="utf-8-sig")
    columns = set(frame.columns)
    target_column = args.path_column if args.path_column in columns else args.text_column
    if target_column not in columns or args.label_column not in columns:
        print(f"Нужны колонки {target_column!r} и {args.label_column!r}; есть: {sorted(columns)}", file=sys.stderr)
        return 1

    category_map = load_category_map(labels_path)
    classifier = build_classifier(
        MlConfig(
            type=args.mode,               # transformer — чистая модель, hybrid — с правилами
            artifact_path=str(model_path),
            labels_file=str(labels_path),
            device=args.device,
            batch_size=args.batch_size,
            hybrid_enabled=args.mode == "hybrid",
        ),
        labels_path=labels_path,
    )
    print(f"Модель: {classifier.describe()}")

    targets = frame[target_column].astype(str).tolist()
    expected_categories = frame[args.label_column].astype(str).tolist()
    assessments = classifier.predict_many(targets)

    predicted_categories: list[str] = []
    predicted_levels: list[str] = []
    expected_levels: list[str] = []
    errors: list[dict[str, str]] = []

    for target, expected, assessment in zip(targets, expected_categories, assessments):
        predicted = max(assessment.scores.items(), key=lambda item: item[1])[0] if assessment.scores else "unknown"
        predicted = predicted.replace("ml:", "")
        predicted_categories.append(predicted)
        predicted_levels.append(assessment.level.value)
        expected_levels.append(category_map.get(expected, SensitivityLevel.INTERNAL.value))
        if predicted != expected and len(errors) < args.errors:
            errors.append({
                "target": target,
                "expected": expected,
                "predicted": predicted,
                "confidence": f"{assessment.confidence:.3f}",
                "reason": assessment.reason,
            })

    category_report = classification_report(expected_categories, predicted_categories, zero_division=0)
    level_report = classification_report(expected_levels, predicted_levels, zero_division=0)
    print("\n=== Категории модели ===")
    print(category_report)
    print(f"accuracy={accuracy_score(expected_categories, predicted_categories):.4f} "
          f"f1_macro={f1_score(expected_categories, predicted_categories, average='macro', zero_division=0):.4f} "
          f"f1_weighted={f1_score(expected_categories, predicted_categories, average='weighted', zero_division=0):.4f}")

    print("=== Классы конфиденциальности (после отображения) ===")
    print(level_report)
    print(f"accuracy={accuracy_score(expected_levels, predicted_levels):.4f} "
          f"f1_macro={f1_score(expected_levels, predicted_levels, average='macro', zero_division=0):.4f}")

    # Разбивка по источникам: csv — родной домен модели, generator — синтетические события
    by_group: dict[str, dict[str, float]] = {}
    group_column = args.group_column
    if group_column and group_column in frame.columns:
        groups = frame[group_column].astype(str).tolist()
        print("=== Разбивка по источникам данных ===")
        for group in sorted(set(groups)):
            indices = [index for index, value in enumerate(groups) if value == group]
            cats_expected = [expected_categories[index] for index in indices]
            cats_predicted = [predicted_categories[index] for index in indices]
            levels_expected = [expected_levels[index] for index in indices]
            levels_predicted = [predicted_levels[index] for index in indices]
            entry = {
                "samples": len(indices),
                "category_accuracy": round(float(accuracy_score(cats_expected, cats_predicted)), 4),
                "category_f1_macro": round(
                    float(f1_score(cats_expected, cats_predicted, average="macro", zero_division=0)), 4),
                "sensitivity_accuracy": round(float(accuracy_score(levels_expected, levels_predicted)), 4),
                "sensitivity_f1_macro": round(
                    float(f1_score(levels_expected, levels_predicted, average="macro", zero_division=0)), 4),
            }
            by_group[group] = entry  # type: ignore[assignment]
            print(f"  {group:<12} примеров={int(entry['samples']):<6} "
                  f"категории: acc={entry['category_accuracy']:.3f} f1={entry['category_f1_macro']:.3f} | "
                  f"классы: acc={entry['sensitivity_accuracy']:.3f} f1={entry['sensitivity_f1_macro']:.3f}")
    print("Матрица ошибок (классы конфиденциальности):")
    labels_order = [level.value for level in SensitivityLevel.labels() if level.value in set(expected_levels + predicted_levels)]
    print(pd.DataFrame(
        confusion_matrix(expected_levels, predicted_levels, labels=labels_order),
        index=[f"ожидалось:{label}" for label in labels_order],
        columns=[f"получено:{label}" for label in labels_order],
    ).to_string())

    if errors:
        print(f"\nПримеры ошибок (до {args.errors}):")
        for item in errors:
            print(f"  {item['target']}: ожидалось {item['expected']}, получено {item['predicted']} "
                  f"({item['confidence']}) — {item['reason'][:120]}")

    if args.output:
        output_path = resolve(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "evaluated_at": datetime.now(tz=timezone.utc).isoformat(),
            "model": str(model_path),
            "dataset": str(dataset_path),
            "mode": args.mode,
            "samples": len(targets),
            "by_source": by_group,
            "category_metrics": {
                "accuracy": float(accuracy_score(expected_categories, predicted_categories)),
                "f1_macro": float(f1_score(expected_categories, predicted_categories, average="macro", zero_division=0)),
                "f1_weighted": float(f1_score(expected_categories, predicted_categories, average="weighted", zero_division=0)),
                "report": category_report,
            },
            "sensitivity_metrics": {
                "accuracy": float(accuracy_score(expected_levels, predicted_levels)),
                "f1_macro": float(f1_score(expected_levels, predicted_levels, average="macro", zero_division=0)),
                "report": level_report,
            },
            "errors": errors,
        }
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nМетрики сохранены: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

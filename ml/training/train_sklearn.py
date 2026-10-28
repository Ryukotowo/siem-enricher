"""Альтернативный классификатор на признаках имени и пути (scikit-learn).

Используется, когда трансформер избыточен (например, на слабом узле SIEM): модель обучается
на детерминированных признаках :mod:`siem_enricher.ml.features` и предсказывает сразу
**класс конфиденциальности** (public/internal/confidential/secret).

Артефакт читается :class:`siem_enricher.ml.classifier.SklearnSensitivityClassifier`::

    {"model": ..., "feature_names": [...], "labels": [...], "model_version": ...,
     "trained_at": ..., "metrics": {...}, "algorithm": ...}

Пример::

    python ml/training/train_sklearn.py --dataset ml/data/processed/files.csv \
        --output ml/artifacts/sensitivity_sklearn.joblib --model-type random_forest
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

from siem_enricher.ml import FEATURE_NAMES, extract_features, features_to_vector, load_category_map  # noqa: E402
from siem_enricher.models.enums import SensitivityLevel  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Обучение классификатора на признаках пути (scikit-learn)")
    parser.add_argument("--dataset", default="ml/data/processed/files.csv")
    parser.add_argument("--output", default="ml/artifacts/sensitivity_sklearn.joblib")
    parser.add_argument("--labels", default="config/sensitivity_labels.json")
    parser.add_argument("--path-column", default="path")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--model-type", choices=["logistic", "random_forest"], default="logistic")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", default="")
    args = parser.parse_args(argv)

    try:
        import joblib
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, classification_report, f1_score
        from sklearn.model_selection import train_test_split
    except ImportError as exc:  # pragma: no cover
        print(f"Не хватает зависимости: {exc}\nУстановите: pip install -r requirements-ml.txt", file=sys.stderr)
        return 2

    def resolve(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else PROJECT_ROOT / path

    dataset_path = resolve(args.dataset)
    if not dataset_path.exists():
        print(f"Датасет не найден: {dataset_path}. Соберите его: python ml/training/build_dataset.py",
              file=sys.stderr)
        return 1

    frame = pd.read_csv(dataset_path, encoding="utf-8")
    path_column = args.path_column if args.path_column in frame.columns else "text"
    if path_column not in frame.columns or args.label_column not in frame.columns:
        print(f"Нужны колонки {path_column!r} и {args.label_column!r}; есть: {list(frame.columns)}", file=sys.stderr)
        return 1

    category_map = load_category_map(resolve(args.labels))
    frame["sensitivity"] = [
        category_map.get(str(label), SensitivityLevel.INTERNAL.value)
        for label in frame[args.label_column]
    ]
    print("Распределение классов конфиденциальности:")
    print(frame["sensitivity"].value_counts().to_string())

    features = [features_to_vector(extract_features(str(path))) for path in frame[path_column]]
    labels = frame["sensitivity"].tolist()

    train_x, eval_x, train_y, eval_y = train_test_split(
        features, labels, test_size=args.test_size, random_state=args.seed, stratify=labels
    )

    if args.model_type == "random_forest":
        model = RandomForestClassifier(n_estimators=300, random_state=args.seed, n_jobs=-1)
    else:
        model = LogisticRegression(max_iter=2000, multi_class="auto", random_state=args.seed)
    model.fit(train_x, train_y)

    predictions = model.predict(eval_x)
    report = classification_report(eval_y, predictions, zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(eval_y, predictions)),
        "f1_macro": float(f1_score(eval_y, predictions, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(eval_y, predictions, average="weighted", zero_division=0)),
    }
    print("\nМетрики на отложенной выборке:")
    print(report)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))

    artifact = {
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "labels": sorted(set(labels)),
        "model_version": args.version or f"sklearn-{args.model_type}-{datetime.now(tz=timezone.utc):%Y%m%d}",
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "algorithm": type(model).__name__,
        "metrics": {**metrics, "report": report},
        "dataset": str(dataset_path),
        "samples": len(labels),
    }
    output_path = resolve(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    print(f"Артефакт сохранён: {output_path}")
    print("Подключение: в config указать ml.type=sklearn и ml.artifact_path=" + str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

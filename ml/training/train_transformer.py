"""Дообучение трансформера для классификации конфиденциальности по именам файлов.

Модель обучается на **коротком тексте** (имя файла, ``max_length`` по умолчанию 64),
как и модель из НИР: ``bert-base-multilingual-cased`` с шестью категориями
(personal, commercial, official_internal, banking, ip, public).

Результат сохраняется в формате, который читает сервис
(:class:`siem_enricher.ml.transformer_classifier.TransformerSensitivityClassifier`):

* ``config.json``, ``model.safetensors``, ``tokenizer.json`` — стандартный чекпоинт HF;
* ``label_encoder.pkl`` — соответствие «индекс -> категория» (``sklearn.LabelEncoder``);
* ``metrics.json`` — метрики на отложенной выборке (для отчёта ВКР).

Пример::

    python ml/training/build_dataset.py --from-csv data/filenames_mixed_dataset.csv
    python ml/training/train_transformer.py --dataset ml/data/processed/files.csv \
        --output ml/artifacts/sensitivity_transformer --epochs 5

Требуется: torch, transformers, scikit-learn, pandas (``pip install -r requirements-ml.txt``).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

DEFAULT_MODEL = "bert-base-multilingual-cased"


def set_seed(seed: int) -> None:
    """Зафиксировать генераторы случайных чисел для воспроизводимости."""
    import numpy as np
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def load_dataset(path: Path, text_column: str, label_column: str) -> Any:
    import pandas as pd

    if not path.exists():
        raise SystemExit(f"Датасет не найден: {path}. Соберите его: python ml/training/build_dataset.py")
    frame = pd.read_csv(path, encoding="utf-8")
    missing = {text_column, label_column} - set(frame.columns)
    if missing:
        raise SystemExit(f"В датасете {path} нет колонок: {sorted(missing)}; есть: {list(frame.columns)}")
    frame = frame.dropna(subset=[text_column, label_column]).copy()
    frame[text_column] = frame[text_column].astype(str).str.strip()
    frame[label_column] = frame[label_column].astype(str).str.strip()
    frame = frame[(frame[text_column] != "") & (frame[label_column] != "")]
    return frame


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Дообучение трансформера классификации конфиденциальности")
    parser.add_argument("--dataset", default="ml/data/processed/files.csv")
    parser.add_argument("--output", default="ml/artifacts/sensitivity_transformer")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--text-column", default="text", help="Колонка с текстом (имя файла)")
    parser.add_argument("--label-column", default="label", help="Колонка с категорией")
    parser.add_argument("--epochs", type=float, default=5.0)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--eval-batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--max-length", type=int, default=64)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="ml/data/interim/mbert_results", help="Каталог промежуточных сохранений")
    args = parser.parse_args(argv)

    try:
        import numpy as np
        import torch
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        from torch.utils.data import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
        import joblib
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        print(f"Не хватает зависимости: {exc}\nУстановите: pip install -r requirements-ml.txt", file=sys.stderr)
        return 2

    set_seed(args.seed)
    dataset_path = Path(args.dataset)
    if not dataset_path.is_absolute():
        dataset_path = PROJECT_ROOT / dataset_path
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = PROJECT_ROOT / output_path
    intermediate = Path(args.output_dir)
    if not intermediate.is_absolute():
        intermediate = PROJECT_ROOT / intermediate

    frame = load_dataset(dataset_path, args.text_column, args.label_column)
    print(f"Примеров в датасете: {len(frame)}")
    print("Распределение категорий:")
    print(frame[args.label_column].value_counts().to_string())

    label_encoder = LabelEncoder()
    frame["label_id"] = label_encoder.fit_transform(frame[args.label_column])
    num_labels = len(label_encoder.classes_)
    print(f"Категорий: {num_labels} -> {list(label_encoder.classes_)}")

    train_texts, eval_texts, train_labels, eval_labels = train_test_split(
        frame[args.text_column].tolist(),
        frame["label_id"].tolist(),
        test_size=args.test_size,
        random_state=args.seed,
        stratify=frame["label_id"].tolist(),
    )

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=num_labels)

    class TextDataset(Dataset):
        """Простейший датасет: тексты токенизируются заранее."""

        def __init__(self, texts: list[str], labels: list[int]) -> None:
            self.encodings = tokenizer(
                texts,
                padding="max_length",
                truncation=True,
                max_length=args.max_length,
                return_tensors="pt",
            )
            self.labels = labels

        def __len__(self) -> int:
            return len(self.labels)

        def __getitem__(self, index: int) -> dict[str, Any]:
            item = {key: value[index] for key, value in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
            return item

    def compute_metrics(prediction: Any) -> dict[str, float]:
        labels = prediction.label_ids
        predictions = np.argmax(prediction.predictions, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="weighted")
        _, _, macro_f1, _ = precision_recall_fscore_support(labels, predictions, average="macro")
        return {
            "accuracy": float(accuracy_score(labels, predictions)),
            "precision_weighted": float(precision),
            "recall_weighted": float(recall),
            "f1_weighted": float(f1),
            "f1_macro": float(macro_f1),
        }

    training_args = TrainingArguments(
        output_dir=str(intermediate),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.eval_batch_size,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="f1_macro",
        greater_is_better=True,
        report_to="none",
        seed=args.seed,
        use_cpu=not torch.cuda.is_available(),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=TextDataset(train_texts, train_labels),
        eval_dataset=TextDataset(eval_texts, eval_labels),
        compute_metrics=compute_metrics,
    )

    print(f"Обучение модели {args.model} (эпох: {args.epochs}, max_length: {args.max_length})...")
    trainer.train()
    metrics = trainer.evaluate()
    print("Метрики на отложенной выборке:")
    print(json.dumps({k: v for k, v in metrics.items() if isinstance(v, (int, float))}, ensure_ascii=False, indent=2))

    output_path.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(output_path))
    tokenizer.save_pretrained(str(output_path))
    joblib.dump(label_encoder, output_path / "label_encoder.pkl")

    version = f"mbert-filenames-{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}"
    report = {
        "model_version": version,
        "base_model": args.model,
        "algorithm": type(model).__name__,
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "dataset_size": int(len(frame)),
        "train_size": len(train_texts),
        "eval_size": len(eval_texts),
        "max_length": args.max_length,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "seed": args.seed,
        "categories": [str(item) for item in label_encoder.classes_],
        "metrics": {k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))},
    }
    (output_path / "metrics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nМодель сохранена: {output_path}")
    print("Файлы: config.json, model.safetensors, tokenizer.json, label_encoder.pkl, metrics.json")
    print("Проверка: python ml/training/evaluate_transformer.py --model " + str(output_path.relative_to(PROJECT_ROOT)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

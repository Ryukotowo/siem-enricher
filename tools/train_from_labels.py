"""Дообучение модели по меткам аналитиков с проверкой качества.

Цикл: экспорт меток (/ui/labels/export) -> датасет -> дообучение ->
сравнение с текущей моделью на отложенной выборке -> сохранение только
если новая модель не хуже.

    python tools/train_from_labels.py --input var/labels/dataset.jsonl --dry-run
    python tools/train_from_labels.py --input var/labels/dataset.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

BASE_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_transformer"
OUTPUT_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_feedback"
REPORT = ROOT / "var" / "labels" / "training_report.json"
LEVELS = ["public", "internal", "confidential", "secret"]
SEED = 42
EPOCHS = 3
MAX_LEN = 64
BATCH = 8
LR = 2e-5


def load_category_map() -> dict[str, str]:
    """Категории базовой модели -> классы конфиденциальности."""
    import json

    config = json.loads((ROOT / "config" / "config.local.json").read_text(encoding="utf-8"))
    path = config.get("labels_path")
    if not path:
        return {}
    from siem_enricher.ml.classifier import load_category_map as load_map

    return load_map(ROOT / path)


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("path") and item.get("level") in LEVELS:
            rows.append(item)
    unique = {}
    for row in rows:
        unique[str(row["path"]).lower()] = row
    return list(unique.values())


def split(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    rng = random.Random(SEED)
    by_level: dict[str, list[dict]] = {}
    for row in rows:
        by_level.setdefault(row["level"], []).append(row)
    train, holdout = [], []
    for items in by_level.values():
        rng.shuffle(items)
        cut = max(1, int(len(items) * 0.8))
        train.extend(items[:cut])
        holdout.extend(items[cut:])
    return train, holdout


def evaluate_model(artifact: Path, rows: list[dict]) -> dict[str, float]:
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


def finetune(train: list[dict], holdout: list[dict], artifact: Path) -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(BASE_ARTIFACT), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(BASE_ARTIFACT), local_files_only=True,
        num_labels=len(LEVELS), ignore_mismatched_sizes=True,
    )
    model.config.id2label = {index: label for index, label in enumerate(LEVELS)}
    model.config.label2id = {label: index for index, label in enumerate(LEVELS)}
    index_of = model.config.label2id

    texts = [row.get("name") or Path(row["path"]).name for row in train]
    targets = [index_of[row["level"]] for row in train]
    optimiser = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    model.train()
    for epoch in range(1, EPOCHS + 1):
        order = list(range(len(texts)))
        random.Random(SEED + epoch).shuffle(order)
        total = correct = 0
        for start in range(0, len(order), BATCH):
            chunk = order[start:start + BATCH]
            batch = tokenizer([texts[index] for index in chunk], truncation=True,
                              max_length=MAX_LEN, padding=True, return_tensors="pt")
            target = torch.tensor([targets[index] for index in chunk])
            logits = model(**batch).logits
            loss = torch.nn.functional.cross_entropy(logits, target)
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += len(chunk)
            correct += int((logits.argmax(dim=-1) == target).sum())
        print(f"  эпоха {epoch}: loss {loss.item():.3f}, точность обучения {correct / total:.3f}")

    artifact.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(artifact))
    tokenizer.save_pretrained(str(artifact))


def main() -> int:
    parser = argparse.ArgumentParser(description="Дообучение по меткам аналитиков")
    parser.add_argument("--input", required=True, help="JSONL из /ui/labels/export")
    parser.add_argument("--dry-run", action="store_true", help="только проверить датасет")
    parser.add_argument("--min-gain", type=float, default=-0.02,
                        help="допустимое падение F1 относительно текущей модели")
    args = parser.parse_args()

    rows = load_rows(Path(args.input))
    if len(rows) < 20:
        print(f"меток мало для обучения: {len(rows)} (нужно минимум 20)")
        return 1

    train, holdout = split(rows)
    counts = {level: sum(1 for row in rows if row["level"] == level) for level in LEVELS}
    print(f"всего меток: {len(rows)} -> обучение {len(train)}, отложенная {len(holdout)}")
    print(f"по классам: {counts}")
    if args.dry_run:
        print("dry-run: обучение не запускается")
        return 0

    print("\n=== текущая модель ===")
    before = evaluate_model(BASE_ARTIFACT, holdout)
    print(f"  {before}")

    print("\n=== дообучение ===")
    finetune(train, holdout, OUTPUT_ARTIFACT)

    print("\n=== новая модель ===")
    after = evaluate_model(OUTPUT_ARTIFACT, holdout)
    print(f"  {after}")

    gain = after["F1"] - before["F1"]
    accepted = gain >= args.min_gain
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps({
        "меток": len(rows), "обучение": len(train), "отложенная": len(holdout),
        "классы": counts, "до": before, "после": after,
        "прирост F1": round(gain, 3), "модель сохранена": accepted,
        "артефакт": str(OUTPUT_ARTIFACT) if accepted else None,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nприрост F1: {gain:+.3f} (порог {args.min_gain:+.3f})")
    print("модель принята" if accepted else "модель отклонена: качество хуже допустимого")
    print(f"отчёт: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Дообучение модели по меткам аналитиков: сильные метки, регрессия, отказ.

Цикл: экспорт меток -> датасет -> дообучение -> сравнение с текущей моделью
на отложенной выборке и на фиксированном регрессионном наборе -> приёмка.

    python tools/train_from_labels.py --input var/labels/dataset.jsonl --dry-run
    python tools/train_from_labels.py --input var/labels/dataset.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

BASE_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_transformer"
DEFAULT_OUTPUT = ROOT / "ml" / "artifacts" / "sensitivity_feedback"
DEFAULT_REJECTED = ROOT / "ml" / "artifacts" / "sensitivity_feedback.rejected"
OUTPUT_ARTIFACT = DEFAULT_OUTPUT
REJECTED_ARTIFACT = DEFAULT_REJECTED
REGRESSION_SET = ROOT / "ml" / "regression_set.jsonl"
REPORT = ROOT / "var" / "labels" / "training_report.json"
LEVELS = ["public", "internal", "confidential", "secret"]
SEED = 42
EPOCHS = 3
MAX_LEN = 64
BATCH = 8
LR = 2e-5
MIN_ROWS = 20


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("path") and item.get("level") in LEVELS:
            rows.append(item)
    return rows


def split(rows: list[dict], share: float = 0.8) -> tuple[list[dict], list[dict]]:
    rng = random.Random(SEED)
    by_level: dict[str, list[dict]] = {}
    for row in rows:
        by_level.setdefault(row["level"], []).append(row)
    train, holdout = [], []
    for items in by_level.values():
        rng.shuffle(items)
        cut = max(1, int(len(items) * share))
        train.extend(items[:cut])
        holdout.extend(items[cut:])
    return train, holdout


def metrics(pairs: list[tuple[str, str]]) -> dict[str, float]:
    correct = sum(1 for truth, pred in pairs if truth == pred)
    positives = {"confidential", "secret"}
    tp = sum(1 for truth, pred in pairs if truth in positives and pred in positives)
    fn = sum(1 for truth, pred in pairs if truth in positives and pred not in positives)
    fp = sum(1 for truth, pred in pairs if truth not in positives and pred in positives)
    _tn = sum(1 for truth, pred in pairs if truth not in positives and pred not in positives)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "по классам": round(correct / len(pairs), 3) if pairs else 0.0,
        "полнота": round(recall, 3),
        "точность": round(precision, 3),
        "F1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "объектов": len(pairs),
    }


def evaluate_model(artifact: Path, rows: list[dict]) -> dict[str, float]:
    """Оценить артефакт через конвейер: он знает и категории, и классы."""
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
    return metrics(pairs)


def finetune(train: list[dict]) -> None:
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

    OUTPUT_ARTIFACT.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUTPUT_ARTIFACT))
    tokenizer.save_pretrained(str(OUTPUT_ARTIFACT))


def reject_artifact() -> None:
    """Отклонённую модель не оставляем среди рабочих артефактов."""
    if not OUTPUT_ARTIFACT.exists():
        return
    if REJECTED_ARTIFACT.exists():
        shutil.rmtree(REJECTED_ARTIFACT, ignore_errors=True)
    OUTPUT_ARTIFACT.rename(REJECTED_ARTIFACT)
    print(f"модель перемещена в {REJECTED_ARTIFACT.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Дообучение по меткам аналитиков")
    parser.add_argument("--input", required=True, help="JSONL из /ui/labels/export")
    parser.add_argument("--dry-run", action="store_true", help="только проверить датасет")
    parser.add_argument("--tenant", default=None,
                        help="организация: артефакт и отчёт попадут в её каталог")
    parser.add_argument("--min-gain", type=float, default=-0.02,
                        help="допустимое падение F1 на отложенной выборке и на регрессии")
    args = parser.parse_args()

    global OUTPUT_ARTIFACT, REJECTED_ARTIFACT, REPORT
    tenant = (args.tenant or "default").strip().lower() or "default"
    if tenant != "default":
        OUTPUT_ARTIFACT = ROOT / "ml" / "artifacts" / tenant / "sensitivity_feedback"
        REJECTED_ARTIFACT = ROOT / "ml" / "artifacts" / tenant / "sensitivity_feedback.rejected"
        REPORT = ROOT / "var" / "labels" / tenant / "training_report.json"
        print(f"организация: {tenant}")

    rows = load_jsonl(Path(args.input))
    strong = [row for row in rows if row.get("strength") == "strong"]
    weak = [row for row in rows if row.get("strength") != "strong"]
    print(f"меток всего: {len(rows)} (сильных {len(strong)}, слабых {len(weak)})")
    if len(rows) < MIN_ROWS:
        print(f"меток мало для обучения: {len(rows)} (нужно минимум {MIN_ROWS})")
        return 1

    base_train = strong if len(strong) >= MIN_ROWS else rows
    if len(strong) < MIN_ROWS:
        print("сильных меток мало: обучение на всём наборе, включая подтверждения без правки класса")

    train, holdout = split(base_train)
    counts = {level: sum(1 for row in base_train if row["level"] == level) for level in LEVELS}
    print(f"обучение {len(train)}, отложенная {len(holdout)}, по классам {counts}")
    if args.dry_run:
        print("dry-run: обучение не запускается")
        return 0

    regression = load_jsonl(REGRESSION_SET)
    print(f"регрессионный набор: {len(regression)} путей")

    print("\n=== текущая модель ===")
    before = evaluate_model(BASE_ARTIFACT, holdout)
    before_reg = evaluate_model(BASE_ARTIFACT, regression) if regression else None
    print(f"  отложенная: {before}")
    if before_reg:
        print(f"  регрессия:  {before_reg}")

    print("\n=== дообучение ===")
    finetune(train)

    print("\n=== новая модель ===")
    after = evaluate_model(OUTPUT_ARTIFACT, holdout)
    after_reg = evaluate_model(OUTPUT_ARTIFACT, regression) if regression else None
    print(f"  отложенная: {after}")
    if after_reg:
        print(f"  регрессия:  {after_reg}")

    gain = after["F1"] - before["F1"]
    regression_delta = (after_reg["F1"] - before_reg["F1"]) if (after_reg and before_reg) else 0.0
    accepted = gain >= args.min_gain and regression_delta >= args.min_gain

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps({
        "меток": len(rows), "сильных": len(strong), "слабых": len(weak),
        "обучение": len(train), "отложенная": len(holdout), "классы": counts,
        "до": before, "после": after,
        "регрессия до": before_reg, "регрессия после": after_reg,
        "прирост F1": round(gain, 3),
        "изменение на регрессии": round(regression_delta, 3),
        "модель сохранена": accepted,
        "артефакт": str(OUTPUT_ARTIFACT) if accepted else None,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nприрост на отложенной: {gain:+.3f} (порог {args.min_gain:+.3f})")
    if before_reg and after_reg:
        print(f"изменение на регрессии: {regression_delta:+.3f}")
    if accepted:
        print("модель принята")
    else:
        reject_artifact()
        print("модель отклонена")
    print(f"отчёт: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

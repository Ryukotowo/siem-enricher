"""Дообучение модели на реальных именах и сравнение на отложенной выборке."""

from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

DATA = ROOT / "var" / "datasets" / "names_1500_masked.jsonl"
BASE_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_transformer"
NEW_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_real"
RESULT = ROOT / "var" / "datasets" / "finetune_result.json"
SEED = 42
EPOCHS = 3
MAX_LEN = 64
BATCH = 16
LR = 2e-5
POSITIVE = {"confidential", "secret"}


def load_rows() -> list[dict]:
    return [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]


def split(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    rng = random.Random(SEED)
    by_level: dict[str, list[dict]] = {}
    for row in rows:
        by_level.setdefault(row["level"], []).append(row)
    train, holdout = [], []
    for level, items in by_level.items():
        rng.shuffle(items)
        cut = max(1, int(len(items) * 0.8))
        train.extend(items[:cut])
        holdout.extend(items[cut:])
    rng.shuffle(train)
    rng.shuffle(holdout)
    return train, holdout


def metrics(pairs: list[tuple[str, str]]) -> dict:
    correct = sum(1 for truth, pred in pairs if truth == pred)
    tp = sum(1 for truth, pred in pairs if truth in POSITIVE and pred in POSITIVE)
    fn = sum(1 for truth, pred in pairs if truth in POSITIVE and pred not in POSITIVE)
    fp = sum(1 for truth, pred in pairs if truth not in POSITIVE and pred in POSITIVE)
    tn = sum(1 for truth, pred in pairs if truth not in POSITIVE and pred not in POSITIVE)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "по классам": round(correct / len(pairs), 3),
        "полнота": round(recall, 3),
        "точность": round(precision, 3),
        "F1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "ложных": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "пропущено": fn,
    }


def evaluate(model_dir: Path, rows: list[dict]) -> dict:
    from siem_enricher.config import load_config
    from siem_enricher.enricher import EnrichmentPipeline
    from siem_enricher.logging_setup import setup_logging

    setup_logging(level="ERROR", fmt="json")
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.artifact_path = str(model_dir)
    config.ml.type = "transformer"
    config.ml.hybrid_enabled = False  # оцениваем саму модель, без правил
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    pairs = [(row["level"], pipeline.classifier.predict(row["path"]).level.value) for row in rows]
    pipeline.close()
    return metrics(pairs)


def finetune(train: list[dict], holdout: list[dict]) -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(BASE_ARTIFACT), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(BASE_ARTIFACT), local_files_only=True,
        num_labels=4, ignore_mismatched_sizes=True,
    )
    new_labels = ["public", "internal", "confidential", "secret"]
    model.config.id2label = {index: label for index, label in enumerate(new_labels)}
    model.config.label2id = {label: index for index, label in enumerate(new_labels)}
    index_of = dict(model.config.label2id)

    missing = {row["level"] for row in train} - set(index_of)
    if missing:
        raise SystemExit(f"нет классов в модели: {missing}")

    texts = [row["name"] for row in train]
    targets = [index_of[row["level"]] for row in train]
    optimiser = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    model.train()
    for epoch in range(1, EPOCHS + 1):
        order = list(range(len(texts)))
        random.Random(SEED + epoch).shuffle(order)
        total, correct = 0, 0
        for start in range(0, len(order), BATCH):
            chunk = order[start:start + BATCH]
            batch = tokenizer([texts[index] for index in chunk], truncation=True, max_length=MAX_LEN,
                              padding=True, return_tensors="pt")
            target = torch.tensor([targets[index] for index in chunk])
            logits = model(**batch).logits
            loss = torch.nn.functional.cross_entropy(logits, target)
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += len(chunk)
            correct += int((logits.argmax(dim=-1) == target).sum())
        print(f"  эпоха {epoch}: loss {loss.item():.3f}, точность обучения {correct / total:.3f}")

    NEW_ARTIFACT.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(NEW_ARTIFACT))
    tokenizer.save_pretrained(str(NEW_ARTIFACT))
    print(f"  модель сохранена: {NEW_ARTIFACT}")


def main() -> int:
    rows = load_rows()
    train, holdout = split(rows)
    print(f"обучение: {len(train)}, отложенная выборка: {len(holdout)}")
    print(f"по классам в отложенной: {dict(Counter(row['level'] for row in holdout))}")

    print("\n=== до дообучения (текущий артефакт, без правил) ===")
    before = evaluate(BASE_ARTIFACT, holdout)
    print(f"  {before}")

    print("\n=== дообучение ===")
    finetune(train, holdout)

    print("\n=== после дообучения ===")
    after = evaluate(NEW_ARTIFACT, holdout)
    print(f"  {after}")

    RESULT.write_text(json.dumps({
        "обучение": len(train), "отложенная": len(holdout),
        "до": before, "после": after,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nрезультат: {RESULT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

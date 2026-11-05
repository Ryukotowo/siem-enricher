"""Прямой замер дообученной модели на отложенной выборке (без маппинга классификатора)."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

DATA = ROOT / "var" / "datasets" / "names_1500_masked.jsonl"
NEW_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_real"
RESULT = ROOT / "var" / "datasets" / "finetune_result.json"
SEED = 42
MAX_LEN = 64
BATCH = 16
POSITIVE = {"confidential", "secret"}


def split(rows: list[dict]) -> list[dict]:
    rng = random.Random(SEED)
    by_level: dict[str, list[dict]] = {}
    for row in rows:
        by_level.setdefault(row["level"], []).append(row)
    holdout: list[dict] = []
    for level, items in by_level.items():
        rng.shuffle(items)
        cut = max(1, int(len(items) * 0.8))
        holdout.extend(items[cut:])
    rng.shuffle(holdout)
    return holdout


def main() -> int:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    holdout = split(rows)

    model = AutoModelForSequenceClassification.from_pretrained(str(NEW_ARTIFACT), local_files_only=True)
    tokenizer = AutoTokenizer.from_pretrained(str(NEW_ARTIFACT), local_files_only=True)
    labels = [str(model.config.id2label[index]) for index in range(len(model.config.id2label))]
    model.eval()

    pairs: list[tuple[str, str]] = []
    for start in range(0, len(holdout), BATCH):
        chunk = holdout[start:start + BATCH]
        batch = tokenizer([row["name"] for row in chunk], truncation=True, max_length=MAX_LEN,
                          padding=True, return_tensors="pt")
        with torch.inference_mode():
            predictions = model(**batch).logits.argmax(dim=-1).tolist()
        for row, index in zip(chunk, predictions):
            pairs.append((row["level"], labels[index]))

    correct = sum(1 for truth, pred in pairs if truth == pred)
    tp = sum(1 for truth, pred in pairs if truth in POSITIVE and pred in POSITIVE)
    fn = sum(1 for truth, pred in pairs if truth in POSITIVE and pred not in POSITIVE)
    fp = sum(1 for truth, pred in pairs if truth not in POSITIVE and pred in POSITIVE)
    tn = sum(1 for truth, pred in pairs if truth not in POSITIVE and pred not in POSITIVE)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    after = {
        "по классам": round(correct / len(pairs), 3),
        "полнота": round(recall, 3),
        "точность": round(precision, 3),
        "F1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "ложных": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "пропущено": fn,
    }
    print(f"отложенная выборка: {len(pairs)}; классы модели: {labels}")
    print(f"после дообучения (прямой замер): {after}")

    if RESULT.exists():
        data = json.loads(RESULT.read_text(encoding="utf-8"))
    else:
        data = {}
    data["после"] = after
    RESULT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

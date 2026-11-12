"""Исправления в дообучении по меткам: база для загрузки и карта классов."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

FINETUNE_OLD = '''def finetune(train: list[dict], holdout: list[dict], artifact: Path) -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(artifact), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(artifact), local_files_only=True, num_labels=len(LEVELS), ignore_mismatched_sizes=True
    )'''
FINETUNE_NEW = '''def finetune(train: list[dict], holdout: list[dict], artifact: Path) -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(BASE_ARTIFACT), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(BASE_ARTIFACT), local_files_only=True,
        num_labels=len(LEVELS), ignore_mismatched_sizes=True,
    )'''

EVAL_OLD = '''    labels = [str(model.config.id2label[index]) for index in range(len(model.config.id2label))]
    model.eval()'''
EVAL_NEW = '''    labels = [str(model.config.id2label[index]) for index in range(len(model.config.id2label))]
    category_map = load_category_map()
    labels = [category_map.get(label, label) for label in labels]
    model.eval()'''

HELPER_ANCHOR = "def load_rows(path: Path) -> list[dict]:"
HELPER = '''def load_category_map() -> dict[str, str]:
    """Категории базовой модели -> классы конфиденциальности."""
    import json

    config = json.loads((ROOT / "config" / "config.local.json").read_text(encoding="utf-8"))
    path = config.get("labels_path")
    if not path:
        return {}
    from siem_enricher.ml.classifier import load_category_map as load_map

    return load_map(ROOT / path)


def load_rows(path: Path) -> list[dict]:'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    if "BASE_ARTIFACT), local_files_only=True," not in text:
        if FINETUNE_OLD not in text:
            print("!! не найден блок finetune")
            return 1
        text = text.replace(FINETUNE_OLD, FINETUNE_NEW, 1)
        changed += 1
        print("обучение загружает базовую модель, а сохраняет в новый артефакт")
    if "category_map = load_category_map()" not in text:
        if EVAL_OLD not in text:
            print("!! не найден блок evaluate")
            return 1
        text = text.replace(EVAL_OLD, EVAL_NEW, 1)
        changed += 1
        print("оценка переводит категории в классы")
    if "def load_category_map()" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("добавлена загрузка карты категорий")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

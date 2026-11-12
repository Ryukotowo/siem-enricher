"""Имена категорий базовой модели: читать label_encoder.pkl, а не только карту."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

HELPER_ANCHOR = "def predict_levels(model, tokenizer, rows: list[dict], category_map: dict[str, str]) -> list[str]:"
HELPER = '''def load_encoder_names(artifact: Path) -> list[str]:
    """Имена категорий из label_encoder.pkl (модель хранит их вне config.json)."""
    path = artifact / "label_encoder.pkl"
    if not path.exists():
        return []
    try:
        import joblib

        encoder = joblib.load(path)
        classes = getattr(encoder, "classes_", None)
        return [str(item) for item in classes] if classes is not None else []
    except Exception:  # noqa: BLE001 - без энкодера остаётся карта по LABEL_N
        return []


def predict_levels('''

USE_OLD = '''    labels = {index: str(name) for index, name in model.config.id2label.items()}'''
USE_NEW = '''    labels = {index: str(name) for index, name in model.config.id2label.items()}
    encoder_names = load_encoder_names(Path(model.config._name_or_path))
    for index, name in list(labels.items()):
        if str(name).startswith("LABEL_") and index < len(encoder_names):
            labels[index] = encoder_names[index]'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    if "def load_encoder_names" not in text:
        if HELPER_ANCHOR not in text:
            print("!! не найден predict_levels")
            return 1
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("predict_levels: имена категорий из label_encoder.pkl")
    if "encoder_names" not in text:
        if USE_OLD not in text:
            print("!! не найдена строка labels")
            return 1
        text = text.replace(USE_OLD, USE_NEW, 1)
        changed += 1
        print("predict_levels: LABEL_N раскрываются через энкодер")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

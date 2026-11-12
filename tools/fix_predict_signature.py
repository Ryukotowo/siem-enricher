"""Восстановить сигнатуру predict_levels."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

OLD = "def predict_levels(\n    import torch"
NEW = ("def predict_levels(model, tokenizer, rows: list[dict], category_map: dict[str, str]) -> list[str]:\n"
       "    import torch")


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найден фрагмент")
        return 1
    text = text.replace(OLD, NEW, 1)
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("сигнатура восстановлена")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

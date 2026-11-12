"""Ключи id2label приводятся к числам: модель хранит их строками."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

OLD = '    labels = {index: str(name) for index, name in model.config.id2label.items()}'
NEW = '    labels = {int(index): str(name) for index, name in model.config.id2label.items()}'


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найдена строка labels")
        return 1
    TOOL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("ключи id2label приведены к int")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Правки тренера: путь энкодера и экономичный оптимизатор."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

ENCODER_OLD = '    encoder_names = load_encoder_names(Path(model.config._name_or_path))'
ENCODER_NEW = '    encoder_names = load_encoder_names(BASE_ARTIFACT)'

OPT_OLD = '''    optimiser = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)'''
OPT_NEW = '''    # SGD с моментом вместо AdamW: состояния оптимизатора не удваивают память,
    # что важно для контейнера с ограниченной RAM.
    optimiser = torch.optim.SGD(model.parameters(), lr=1e-3, momentum=0.9)'''

CHECKPOINT_OLD = '''    print("\\n=== дообучение ===")
    replace_head(model)'''
CHECKPOINT_NEW = '''    print("\\n=== дообучение ===")
    replace_head(model)
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (ENCODER_OLD, ENCODER_NEW, "энкодер читается из базового артефакта"),
        (OPT_OLD, OPT_NEW, "SGD вместо AdamW"),
        (CHECKPOINT_OLD, CHECKPOINT_NEW, "gradient checkpointing"),
    ):
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print(f"  {label}")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

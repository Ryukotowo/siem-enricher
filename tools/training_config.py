"""Пороги приёмки модели в конфигурации вместо флагов CLI."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"
TOOL = ROOT / "tools" / "train_from_labels.py"

FIELD_OLD = "    hybrid_policy_override: bool = True"
FIELD_NEW = '''    hybrid_policy_override: bool = True
    training_min_gain: float = -0.02
    training_regression_limit: int = 120
    training_min_rows: int = 20
    training_epochs: int = 3
    training_learning_rate: float = 2e-5'''

DEFAULTS_OLD = '        "confidence_floor": 0.35,'
DEFAULTS_NEW = '''        "confidence_floor": 0.35,
        "training_min_gain": -0.02,
        "training_regression_limit": 120,
        "training_min_rows": 20,
        "training_epochs": 3,
        "training_learning_rate": 2e-5,'''

# --- тренер: значения по умолчанию берутся из конфигурации ---

ARGS_OLD = '''    parser.add_argument("--regression-limit", type=int, default=120,
                        help="сколько путей регрессионного набора проверять (0 — все)")'''
ARGS_NEW = '''    parser.add_argument("--regression-limit", type=int, default=None,
                        help="сколько путей регрессионного набора проверять (0 — все)")'''

GAIN_OLD = '''    parser.add_argument("--min-gain", type=float, default=-0.02,
                        help="допустимое падение F1 на отложенной выборке и на регрессии")'''
GAIN_NEW = '''    parser.add_argument("--min-gain", type=float, default=None,
                        help="допустимое падение F1 на отложенной выборке и на регрессии")'''

RESOLVE_OLD = '''    tenant = (args.tenant or "default").strip().lower() or "default"'''
RESOLVE_NEW = '''    from siem_enricher.config import load_config

    settings = load_config(ROOT / "config" / "config.local.json").ml
    min_gain = args.min_gain if args.min_gain is not None else settings.training_min_gain
    regression_limit = (args.regression_limit if args.regression_limit is not None
                        else settings.training_regression_limit)
    epochs = settings.training_epochs
    learning_rate = settings.training_learning_rate
    min_rows = settings.training_min_rows

    tenant = (args.tenant or "default").strip().lower() or "default"'''

USES = [
    ("    if len(rows) < MIN_ROWS:", "    if len(rows) < min_rows:"),
    ("    for epoch in range(1, EPOCHS + 1):", "    for epoch in range(1, epochs + 1):"),
    ("    optimiser = torch.optim.SGD(model.parameters(), lr=1e-3, momentum=0.9)",
     "    optimiser = torch.optim.SGD(model.parameters(), lr=learning_rate, momentum=0.9)"),
    ("    if args.regression_limit and len(regression) > args.regression_limit:\n        regression = regression[:args.regression_limit]",
     "    if regression_limit and len(regression) > regression_limit:\n        regression = regression[:regression_limit]"),
    ("    accepted = gain >= args.min_gain and regression_delta >= args.min_gain",
     "    accepted = gain >= min_gain and regression_delta >= min_gain"),
    ('    print(f"\\nприрост на отложенной: {gain:+.3f} (порог {args.min_gain:+.3f})")',
     '    print(f"\\nприрост на отложенной: {gain:+.3f} (порог {min_gain:+.3f})")'),
]


def patch_config() -> int:
    text = CONFIG.read_text(encoding="utf-8")
    changed = 0
    if "training_min_gain" not in text:
        if FIELD_OLD not in text or DEFAULTS_OLD not in text:
            print("!! не найдены поля MlConfig")
            return 0
        text = text.replace(FIELD_OLD, FIELD_NEW, 1)
        text = text.replace(DEFAULTS_OLD, DEFAULTS_NEW, 1)
        CONFIG.write_text(text, encoding="utf-8")
        ast.parse(text)
        changed = 1
        print("config: ml.training_*")
    return changed


def patch_tool() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0

    def apply(old: str, new: str, label: str) -> None:
        nonlocal text, changed
        if new.strip() and new in text:
            return
        if old not in text:
            print(f"  предупреждение: не найдено для «{label}»")
            return
        text = text.replace(old, new, 1)
        changed += 1
        print(f"  {label}")

    apply(ARGS_OLD, ARGS_NEW, "порог регрессии из конфига")
    apply(GAIN_OLD, GAIN_NEW, "порог F1 из конфига")
    apply(RESOLVE_OLD, RESOLVE_NEW, "чтение настроек обучения")
    for old, new in USES:
        apply(old, new, f"использование {new.strip().split()[0]}")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    return changed


def main() -> int:
    print("конфигурация:")
    patch_config()
    print("тренер:")
    patch_tool()
    print("готово")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

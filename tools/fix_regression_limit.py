"""Применить ограничение размера регрессионного набора."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

OLD = '    regression = load_jsonl(REGRESSION_SET)\n    print(f"регрессионный набор: {len(regression)} путей")'
NEW = ('    regression = load_jsonl(REGRESSION_SET)\n'
       '    if args.regression_limit and len(regression) > args.regression_limit:\n'
       '        regression = regression[:args.regression_limit]\n'
       '    print(f"регрессионный набор: {len(regression)} путей")')


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if "regression[:args.regression_limit]" in text:
        print("уже применено")
        return 0
    if OLD not in text:
        print("!! не найден блок чтения регрессии")
        return 1
    TOOL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("регрессия ограничивается параметром --regression-limit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

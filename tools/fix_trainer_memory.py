"""Экономия памяти при обучении в контейнере: освобождать модель после оценки."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

OLD = '''    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    try:
        pairs = [(row["level"], pipeline.classifier.predict(row["path"]).level.value) for row in rows]
    finally:
        pipeline.close()
    return metrics(pairs)'''

NEW = '''    import gc

    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    try:
        pairs = [(row["level"], pipeline.classifier.predict(row["path"]).level.value) for row in rows]
    finally:
        pipeline.close()
        del pipeline
        gc.collect()
    return metrics(pairs)'''

LIMIT_OLD = '''    parser.add_argument("--tenant", default=None,'''
LIMIT_NEW = '''    parser.add_argument("--regression-limit", type=int, default=120,
                        help="сколько путей регрессионного набора проверять (0 — все)")
    parser.add_argument("--tenant", default=None,'''

USE_OLD = '''    regression = load_jsonl(REGRESSION_SET)'''
USE_NEW = '''    regression = load_jsonl(REGRESSION_SET)
    if args.regression_limit and len(regression) > args.regression_limit:
        regression = regression[:args.regression_limit]'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (OLD, NEW, "освобождение памяти после оценки"),
        (LIMIT_OLD, LIMIT_NEW, "параметр --regression-limit"),
        (USE_OLD, USE_NEW, "ограничение размера регрессии"),
    ):
        if new.split("\n")[0] in text:
            continue
        if old not in text:
            print(f"  предупреждение: не найдено для «{label}»")
            continue
        text = text.replace(old, new, 1)
        changed += 1
        print(f"  {label}")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

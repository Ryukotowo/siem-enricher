"""Тренер учитывает организацию: артефакт и отчёт в её каталоге."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

ANCHOR = 'OUTPUT_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_feedback"'
NEW_CONSTS = '''DEFAULT_OUTPUT = ROOT / "ml" / "artifacts" / "sensitivity_feedback"
DEFAULT_REJECTED = ROOT / "ml" / "artifacts" / "sensitivity_feedback.rejected"
OUTPUT_ARTIFACT = DEFAULT_OUTPUT
REJECTED_ARTIFACT = DEFAULT_REJECTED'''

ARGS_ANCHOR = '''    parser.add_argument("--min-gain", type=float, default=-0.02,'''
ARGS_NEW = '''    parser.add_argument("--tenant", default=None,
                        help="организация: артефакт и отчёт попадут в её каталог")
    parser.add_argument("--min-gain", type=float, default=-0.02,'''

APPLY_ANCHOR = '''    rows = load_jsonl(Path(args.input))'''
APPLY_NEW = '''    global OUTPUT_ARTIFACT, REJECTED_ARTIFACT, REPORT
    tenant = (args.tenant or "default").strip().lower() or "default"
    if tenant != "default":
        OUTPUT_ARTIFACT = ROOT / "ml" / "artifacts" / tenant / "sensitivity_feedback"
        REJECTED_ARTIFACT = ROOT / "ml" / "artifacts" / tenant / "sensitivity_feedback.rejected"
        REPORT = ROOT / "var" / "labels" / tenant / "training_report.json"
        print(f"организация: {tenant}")

    rows = load_jsonl(Path(args.input))'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    if "DEFAULT_OUTPUT" not in text:
        if ANCHOR not in text:
            print("!! не найдены константы вывода")
            return 1
        text = text.replace(ANCHOR, NEW_CONSTS, 1)
        text = text.replace('REJECTED_ARTIFACT = ROOT / "ml" / "artifacts" / "sensitivity_feedback.rejected"\n', "", 1)
        changed += 1
    for old, new in ((ARGS_ANCHOR, ARGS_NEW), (APPLY_ANCHOR, APPLY_NEW)):
        if old in text and new.split("\n")[0] not in text:
            text = text.replace(old, new, 1)
            changed += 1
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

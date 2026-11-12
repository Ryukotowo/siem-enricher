"""Регистрация принятой модели в реестре версий и запись в аудит."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "train_from_labels.py"

IMPORT_ANCHOR = "    import torch\n    from transformers import AutoModelForSequenceClassification, AutoTokenizer"
IMPORT_NEW = ("    import torch\n    from transformers import AutoModelForSequenceClassification, AutoTokenizer\n"
              "    from siem_enricher.ml.registry import ModelRegistry, ACTIVE_NAME")

SAVE_OLD = '''    if accepted:
        OUTPUT_ARTIFACT.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(OUTPUT_ARTIFACT))
        tokenizer.save_pretrained(str(OUTPUT_ARTIFACT))'''
SAVE_NEW = '''    registry = ModelRegistry(tenant)
    if accepted:
        staged = ROOT / "ml" / "artifacts" / ".staging"
        if staged.exists():
            import shutil

            shutil.rmtree(staged, ignore_errors=True)
        staged.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(staged))
        tokenizer.save_pretrained(str(staged))
        record = registry.register(
            staged,
            {"до": before, "после": after,
             "регрессия до": before_reg, "регрессия после": after_reg},
            note=f"меток {len(rows)}, сильных {len(strong)}",
            actor="trainer",
        )
        import shutil

        shutil.rmtree(staged, ignore_errors=True)
        OUTPUT_ARTIFACT = Path(record["artifact"])
        print(f"версия модели: {record['id']} -> {registry.active_path().name}")'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    if "ModelRegistry" not in text:
        if IMPORT_ANCHOR not in text:
            print("!! не найден блок импортов")
            return 1
        text = text.replace(IMPORT_ANCHOR, IMPORT_NEW, 1)
        changed += 1
        print("  импорт реестра")
    if "registry.register(" not in text:
        if SAVE_OLD not in text:
            print("!! не найден блок сохранения")
            return 1
        text = text.replace(SAVE_OLD, SAVE_NEW, 1)
        changed += 1
        print("  принятая модель регистрируется как версия")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

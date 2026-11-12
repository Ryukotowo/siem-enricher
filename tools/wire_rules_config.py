"""Подключение правил из конфигурации к построению классификатора."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "src" / "siem_enricher" / "ml" / "classifier.py"
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"

IMPORT_OLD = "from siem_enricher.ml.fallback_rules import"
IMPORT_NEW = "from siem_enricher.ml.rules_config import load_rules\nfrom siem_enricher.ml.fallback_rules import"

BUILD_OLD = '''    rules = HeuristicSensitivityClassifier(
        default_level=SensitivityLevel.from_value(config.default_level, default=SensitivityLevel.INTERNAL),
        model_version=explicit_version or HEURISTIC_VERSION,
        confidence_floor=config.confidence_floor,
    )'''
BUILD_NEW = '''    spec = load_rules(getattr(config, "rules_file", None))
    if spec.errors:
        logger.warning("Правила из конфигурации загружены с замечаниями",
                       extra={"errors": spec.errors, "file": str(spec.source)})
    rules = HeuristicSensitivityClassifier(
        default_level=SensitivityLevel.from_value(config.default_level, default=SensitivityLevel.INTERNAL),
        model_version=explicit_version or HEURISTIC_VERSION,
        confidence_floor=config.confidence_floor,
        filename_rules=spec.filename_rules,
        directory_rules=spec.directory_rules,
        extension_rules=spec.extension_rules,
    )'''

FIELD_OLD = "    labels_file: str = \"config/sensitivity_labels.json\""
FIELD_NEW = ("    labels_file: str = \"config/sensitivity_labels.json\"\n"
             "    rules_file: str = \"config/rules.json\"")


def main() -> int:
    text = CLASSIFIER.read_text(encoding="utf-8")
    changed = 0
    if "load_rules" not in text:
        if IMPORT_OLD not in text:
            print("!! не найден импорт fallback_rules")
            return 1
        text = text.replace(IMPORT_OLD, IMPORT_NEW, 1)
        changed += 1
    if BUILD_NEW not in text:
        if BUILD_OLD not in text:
            print("!! не найден блок построения правил")
            return 1
        text = text.replace(BUILD_OLD, BUILD_NEW, 1)
        changed += 1
    CLASSIFIER.write_text(text, encoding="utf-8")
    ast.parse(text)

    config_text = CONFIG.read_text(encoding="utf-8")
    if "rules_file" not in config_text:
        if FIELD_OLD in config_text:
            config_text = config_text.replace(FIELD_OLD, FIELD_NEW, 1)
            CONFIG.write_text(config_text, encoding="utf-8")
            ast.parse(config_text)
            changed += 1
            print("config: добавлено поле ml.rules_file")
        else:
            print("  предупреждение: не найдено поле labels_file")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

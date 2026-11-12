"""Настройки и артефакт по организации: пути и вызовы."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
CLASSIFIER = ROOT / "src" / "siem_enricher" / "ml" / "classifier.py"

SETTINGS_OLD = '''def _settings_path() -> Path:
    from pathlib import Path

    candidate = Path.cwd() / SETTINGS_FILE
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate'''
SETTINGS_NEW = '''def _settings_path(app: Any = None) -> Path:
    """Файл настроек организации: у каждой свой."""
    from pathlib import Path

    tenant = "default"
    config = getattr(getattr(app, "state", None), "config", None) if app is not None else None
    if config is not None:
        tenant = current_tenant(config)
    name = SETTINGS_FILE if tenant == "default" else f"var/runtime-settings-{tenant}.json"
    candidate = Path.cwd() / name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate'''

CALL_OLD = "model_path=str(resolve_artifact_path(config.artifact_path)),"
CALL_NEW = ("model_path=str(resolve_artifact_path(config.artifact_path, "
            "current_tenant_from_ml(config))),")


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if SETTINGS_NEW not in text:
        if SETTINGS_OLD not in text:
            print("!! не найден _settings_path")
            return 1
        text = text.replace(SETTINGS_OLD, SETTINGS_NEW, 1)
        changed += 1
        print("panel: путь настроек по организации")
    if "_settings_path()" in text:
        text = text.replace("_settings_path()", "_settings_path(app)")
        changed += 1
        print("panel: вызовы получают приложение")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)

    classifier_text = CLASSIFIER.read_text(encoding="utf-8")
    if CALL_NEW not in classifier_text:
        if CALL_OLD not in classifier_text:
            print("  предупреждение: не найден вызов resolve_artifact_path")
        else:
            classifier_text = classifier_text.replace(CALL_OLD, CALL_NEW, 1)
            helper = '''def current_tenant_from_ml(config: Any) -> str:
    """Организация для выбора артефакта (по конфигурации сервиса)."""
    service = getattr(config, "service", None) or getattr(config, "_service", None)
    return str(getattr(service, "tenant", "default") or "default")


'''
            anchor = "def resolve_artifact_path("
            classifier_text = classifier_text.replace(anchor, helper + anchor, 1)
            CLASSIFIER.write_text(classifier_text, encoding="utf-8")
            ast.parse(classifier_text)
            changed += 1
            print("classifier: выбор артефакта по организации сервиса")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

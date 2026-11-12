"""Разделение данных по организациям: tenant в конфигурации и путях."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"
CLASSIFIER = ROOT / "src" / "siem_enricher" / "ml" / "classifier.py"
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

CONFIG_FIELD_OLD = '    log_format: str = "json"'
CONFIG_FIELD_NEW = '    log_format: str = "json"\n    tenant: str = "default"'

CONFIG_DEFAULT_OLD = '        "log_format": "json",'
CONFIG_DEFAULT_NEW = '        "log_format": "json",\n        "tenant": "default",'

TENANT_HELPER = '''def current_tenant(config: Any) -> str:
    """Идентификатор организации из конфигурации (``default`` — общий режим)."""
    import re

    service = getattr(config, "service", None)
    raw = str(getattr(service, "tenant", "default") or "default").strip().lower()
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", raw).strip("-.")
    return cleaned or "default"


'''

CLASSIFIER_OLD = "def resolve_artifact_path(path: str | Path) -> Path:"
CLASSIFIER_NEW = "def resolve_artifact_path(path: str | Path, tenant: str | None = None) -> Path:"

CLASSIFIER_ROOT_OLD = '''    root = Path.cwd() / "ml" / "artifacts"
    if not root.exists():
        return Path(raw)'''
CLASSIFIER_ROOT_NEW = '''    base = Path.cwd() / "ml" / "artifacts"
    if not base.exists():
        return Path(raw)

    root = base
    if tenant and tenant != "default":
        scoped = base / tenant
        if scoped.exists() and any(
            (item / "config.json").exists() for item in scoped.iterdir() if item.is_dir()
        ):
            root = scoped
    if not root.exists():
        return Path(raw)'''

LABELS_OLD = '''def _labels_path() -> Any:
    from pathlib import Path as _Path

    path = _Path.cwd() / LABELS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    return path'''
LABELS_NEW = '''def _labels_path(app: Any = None) -> Any:
    """Файл меток организации: у каждой свой каталог."""
    from pathlib import Path as _Path

    tenant = "default"
    config = getattr(getattr(app, "state", None), "config", None) if app is not None else None
    if config is not None:
        tenant = current_tenant(config)
    if tenant == "default":
        path = _Path.cwd() / LABELS_FILE
    else:
        path = _Path.cwd() / "var" / "labels" / tenant / "analyst_labels.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path'''

SETTINGS_OLD = '''def _settings_path() -> "Path":
    from pathlib import Path

    candidate = Path.cwd() / SETTINGS_FILE
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate'''
SETTINGS_NEW = '''def _settings_path(app: Any = None) -> "Path":
    from pathlib import Path

    tenant = "default"
    config = getattr(getattr(app, "state", None), "config", None) if app is not None else None
    if config is not None:
        tenant = current_tenant(config)
    name = SETTINGS_FILE if tenant == "default" else f"var/runtime-settings-{tenant}.json"
    candidate = Path.cwd() / name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate'''


def main() -> int:
    changed = 0

    config_text = CONFIG.read_text(encoding="utf-8")
    if "tenant" not in config_text:
        if CONFIG_FIELD_OLD not in config_text or CONFIG_DEFAULT_OLD not in config_text:
            print("!! не найдены поля ServiceConfig")
            return 1
        config_text = config_text.replace(CONFIG_FIELD_OLD, CONFIG_FIELD_NEW, 1)
        config_text = config_text.replace(CONFIG_DEFAULT_OLD, CONFIG_DEFAULT_NEW, 1)
        CONFIG.write_text(config_text, encoding="utf-8")
        ast.parse(config_text)
        changed += 1
        print("config: service.tenant")

    panel_text = PANEL.read_text(encoding="utf-8")
    if "def current_tenant" not in panel_text:
        panel_text = panel_text.replace("LABELS_FILE = ", TENANT_HELPER + "LABELS_FILE = ", 1)
        changed += 1
        print("панель: current_tenant()")
    for old, new, label in (
        (LABELS_OLD, LABELS_NEW, "путь меток по организации"),
        (SETTINGS_OLD, SETTINGS_NEW, "путь настроек по организации"),
    ):
        if old in panel_text:
            panel_text = panel_text.replace(old, new, 1)
            changed += 1
            print(f"панель: {label}")
    if "_labels_path()" in panel_text:
        panel_text = panel_text.replace("_labels_path()", "_labels_path(app)")
        changed += 1
    PANEL.write_text(panel_text, encoding="utf-8")
    ast.parse(panel_text)

    classifier_text = CLASSIFIER.read_text(encoding="utf-8")
    if "tenant: str | None = None" not in classifier_text:
        classifier_text = classifier_text.replace(CLASSIFIER_OLD, CLASSIFIER_NEW, 1)
        classifier_text = classifier_text.replace(CLASSIFIER_ROOT_OLD, CLASSIFIER_ROOT_NEW, 1)
        CLASSIFIER.write_text(classifier_text, encoding="utf-8")
        ast.parse(classifier_text)
        changed += 1
        print("classifier: артефакт с учётом организации")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

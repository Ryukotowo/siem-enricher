"""Вставка хелперов панели и флага отключения по факту структуры файла."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

HELPERS = '''def _panel_setting(app, name, default=None):
    """Настройка панели: конфиг, переменная окружения или var/panel-settings.json."""
    import json as _json
    import os
    from pathlib import Path as _Path

    config = getattr(app.state, "config", None)
    section = getattr(config, "panel", None)
    value = getattr(section, name, None) if section is not None else None
    if value in (None, ""):
        value = os.environ.get("SIEM_PANEL_" + name.upper())
    if value in (None, ""):
        try:
            stored = _json.loads((_Path.cwd() / "var" / "panel-settings.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = {}
        value = stored.get(name)
    return default if value in (None, "") else value


def siem_link_template(app) -> str:
    """Шаблон ссылки на событие в SIEM (пусто — ссылку не показываем)."""
    return str(_panel_setting(app, "siem_url_template", "") or "")


def register_panel(app, buffer) -> bool:'''

ANCHOR = "def register_panel(app: Any, buffer: EventBuffer) -> bool:"

ENABLED_OLD = '''def register_panel(app, buffer) -> bool:
    """'''
ENABLED_NEW = '''def register_panel(app, buffer) -> bool:
    if str(_panel_setting(app, "enabled", True)).lower() in {"0", "false", "no", "off"}:
        return False
    """'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "_panel_setting" in text:
        print("хелперы уже есть")
        return 0
    if ANCHOR not in text:
        print("!! не найден register_panel")
        return 1
    text = text.replace(ANCHOR, HELPERS, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("хелперы добавлены")

    settings = ROOT / "var" / "panel-settings.json"
    if not settings.exists():
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text(json.dumps({
            "enabled": True,
            "siem_url_template":
                "http://localhost:7280/ui/search?indexId=siem-enriched&query=event_id:{event_id}",
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print("создан panel-settings.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

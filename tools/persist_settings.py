"""Сохранение настроек панели между перезапусками."""

from __future__ import annotations

import ast
import json
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPERS = '''SETTINGS_FILE = "var/runtime-settings.json"


def _settings_path() -> "Path":
    from pathlib import Path

    candidate = Path.cwd() / SETTINGS_FILE
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def persist_settings(values: dict[str, Any]) -> None:
    """Сохранить действующие параметры, чтобы пережить перезапуск."""
    import json

    try:
        _settings_path().write_text(
            json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def restore_settings(app: Any) -> list[str]:
    """Один раз применить параметры, сохранённые в прошлый раз."""
    if getattr(app.state, "settings_restored", False):
        return []
    app.state.settings_restored = True
    import json

    path = _settings_path()
    if not path.exists():
        return []
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(saved, dict):
        return []
    applied, _errors = apply_settings(app, saved)
    return applied


'''

APPLY_ANCHOR = "    return applied, errors\n\n\ndef register_panel("
APPLY_NEW = '''    if applied:
        persist_settings(merged)
    return applied, errors


def register_panel('''

GET_ANCHOR = '''    async def panel_config(request: Request) -> Any:
        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app)})'''
GET_NEW = '''    async def panel_config(request: Request) -> Any:
        restore_settings(request.app)
        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app)})'''

POST_ANCHOR = '''        applied, errors = apply_settings(request.app, payload.get("values", {}))'''
POST_NEW = '''        restore_settings(request.app)
        applied, errors = apply_settings(request.app, payload.get("values", {}))'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "restore_settings" in text:
        print("уже есть")
        return 0
    if APPLY_ANCHOR not in text:
        print("!! не найдено место после apply_settings")
        return 1
    text = text.replace(APPLY_ANCHOR, APPLY_NEW, 1)
    text = text.replace("def register_panel(", HELPERS + "def register_panel(", 1)
    text = text.replace(GET_ANCHOR, GET_NEW, 1)
    text = text.replace(POST_ANCHOR, POST_NEW, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("патч применён, синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

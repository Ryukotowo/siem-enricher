"""Ссылка в SIEM из карточки события и флаг отключения панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPERS = '''def _panel_setting(app: Any, name: str, default: Any = None) -> Any:
    """Настройка панели: сначала конфиг, затем переменная окружения."""
    import os

    config = getattr(app.state, "config", None)
    section = getattr(config, "panel", None)
    value = getattr(section, name, None) if section is not None else None
    if value in (None, ""):
        value = os.environ.get(f"SIEM_PANEL_{name.upper()}", default)
    return value


def siem_link_template(app: Any) -> str:
    """Шаблон ссылки на событие в SIEM (пусто — ссылку не показываем)."""
    return str(_panel_setting(app, "siem_url_template", "") or "")


def register_panel('''

ENABLED = '''def register_panel(app: Any, buffer: EventBuffer) -> bool:
    """Подключить панель к приложению FastAPI (если он установлен)."""
    if str(_panel_setting(app, "enabled", "1")).lower() in {"0", "false", "no", "off"}:
        return False
'''
ENABLED_OLD = '''def register_panel(app: Any, buffer: EventBuffer) -> bool:
    """Подключить панель к приложению FastAPI (если он установлен)."""
'''

CONFIG_LINE_OLD = '''        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app),
                             "rules": read_rules(request.app)})'''
CONFIG_LINE_NEW = '''        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app),
                             "rules": read_rules(request.app),
                             "siem_url_template": siem_link_template(request.app)})'''

JS_HOOK_OLD = '''  <div class="row"><div class="k">идентификатор события</div>'''
JS_HOOK_NEW = '''  ${siemLink(event)}
  <div class="row"><div class="k">идентификатор события</div>'''

JS_FUNC_ANCHOR = "function renderDetail("
JS_FUNC = '''let SIEM_TEMPLATE = '';

function siemLink(event) {
  if (!SIEM_TEMPLATE) return '';
  const url = SIEM_TEMPLATE.replaceAll('{event_id}', encodeURIComponent(event.event_id || ''))
                            .replaceAll('{file}', encodeURIComponent(event.file || ''));
  return `<div class="row"><div class="k">в системе SIEM</div>
    <div class="v"><a href="${url}" target="_blank" rel="noopener">открыть событие в SIEM →</a></div></div>`;
}

async function loadPanelMeta() {
  try {
    const response = await fetch('/ui/config', {cache: 'no-store'});
    if (!response.ok) return;
    const payload = await response.json();
    SIEM_TEMPLATE = payload.siem_url_template || '';
    if (SIEM_TEMPLATE && SELECTED) render();
  } catch (error) { /* панель работает и без ссылки */ }
}

function renderDetail('''

CALL_ANCHOR = "connectStream();"


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "siemLink" in text:
        print("ссылка уже есть")
        return 0
    pairs = [
        ("def register_panel(app: Any, buffer: EventBuffer) -> bool:", HELPERS),
        (ENABLED_OLD, ENABLED),
        (CONFIG_LINE_OLD, CONFIG_LINE_NEW),
        (JS_HOOK_OLD, JS_HOOK_NEW),
        (JS_FUNC_ANCHOR, JS_FUNC),
        (CALL_ANCHOR, CALL_ANCHOR + "\nloadPanelMeta();"),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:52]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:50]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

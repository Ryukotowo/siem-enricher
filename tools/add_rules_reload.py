"""Горячая перезагрузка правил из конфигурации через панель."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPER_ANCHOR = "def read_rules(app: Any) -> list[dict[str, Any]]:"
HELPER = '''def reload_rules(app: Any) -> dict[str, Any]:
    """Пересобрать классификатор по файлу правил без перезапуска сервиса."""
    pipeline = _pipeline_of(app)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    from siem_enricher.ml.classifier import build_classifier

    fresh = build_classifier(config.ml, None, labels_path=config.labels_path)
    pipeline.classifier = fresh
    directory_rules = getattr(getattr(fresh, "rules", fresh), "directory_rules", None)
    _audit(app, {"kind": "rules_reload", "key": "config/rules.json",
                 "from": "-", "to": getattr(fresh, "model_version", "unknown")})
    return {
        "ok": True,
        "model_version": getattr(fresh, "model_version", "unknown"),
        "rules": len(directory_rules) if directory_rules is not None else None,
    }


def read_rules(app: Any) -> list[dict[str, Any]]:'''

ROUTE_ANCHOR = '    @app.get("/ui/labels/export", include_in_schema=False)'
ROUTE = '''    @app.post("/ui/rules/reload", include_in_schema=False)
    async def panel_rules_reload(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        result = reload_rules(request.app)
        status = 200 if result.get("ok") else 400
        return JSONResponse(result, status_code=status)

'''

UI_OLD = '      <button class="save" id="settings-save">применить</button>'
UI_NEW = ('      <button class="cancel" id="rules-reload">перечитать правила</button>\n'
          '      <button class="save" id="settings-save">применить</button>')

JS_OLD = "document.getElementById('settings-save').addEventListener('click', saveSettings);"
JS_NEW = '''document.getElementById('settings-save').addEventListener('click', saveSettings);

const rulesReload = document.getElementById('rules-reload');
if (rulesReload) {
  rulesReload.addEventListener('click', async () => {
    try {
      const response = await fetch('/ui/rules/reload', {
        method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-Analyst': 'panel'}
      });
      const payload = await response.json();
      SETTINGS_RESULT.textContent = payload.ok
        ? 'правила перечитаны: ' + payload.model_version + ' (' + payload.rules + ' каталогов)'
        : 'не удалось: ' + (payload.error || 'неизвестная ошибка');
    } catch (error) {
      SETTINGS_RESULT.textContent = 'не удалось: ' + error.message;
    }
  });
}'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "reload_rules" in text:
        print("уже есть")
        return 0
    pairs = [
        (HELPER_ANCHOR, HELPER),
        (ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR),
        (UI_OLD, UI_NEW),
        (JS_OLD, JS_NEW),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("панель: перезагрузка правил и кнопка в настройках")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Тумблеры правил политик в настройках панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPERS = '''def read_rules(app: Any) -> list[dict[str, Any]]:
    """Список правил политик с их состоянием."""
    engine = getattr(_pipeline_of(app), "policy_engine", None)
    rules = getattr(engine, "rules", None) or []
    return [{"id": rule.id, "title": rule.title or "", "enabled": bool(rule.enabled)}
            for rule in rules]


def apply_rules(app: Any, changes: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Включить или выключить правила политик на лету."""
    engine = getattr(_pipeline_of(app), "policy_engine", None)
    if engine is None:
        return [], ["движок политик недоступен"]
    by_id = {rule.id: rule for rule in getattr(engine, "rules", [])}
    applied: list[str] = []
    errors: list[str] = []
    for rule_id, enabled in (changes or {}).items():
        rule = by_id.get(str(rule_id))
        if rule is None:
            errors.append(f"правило {rule_id} не найдено")
            continue
        rule.enabled = bool(enabled)
        applied.append(str(rule_id))
    return applied, errors


def read_settings(app: Any) -> dict[str, Any]:'''

PERSIST_OLD = '''def persist_settings(values: dict[str, Any]) -> None:
    """Сохранить действующие параметры, чтобы пережить перезапуск."""
    import json

    try:
        _settings_path().write_text(
            json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass'''
PERSIST_NEW = '''def persist_settings(values: dict[str, Any], rules: dict[str, Any] | None = None) -> None:
    """Сохранить действующие параметры и состояние правил, чтобы пережить перезапуск."""
    import json

    payload = {"values": values, "rules": rules or {}}
    try:
        _settings_path().write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass'''

RESTORE_OLD = '''    if not isinstance(saved, dict):
        return []
    applied, _errors = apply_settings(app, saved)
    return applied'''
RESTORE_NEW = '''    if not isinstance(saved, dict):
        return []
    values = saved.get("values") if isinstance(saved.get("values"), dict) else saved
    applied, _errors = apply_settings(app, values)
    if isinstance(saved.get("rules"), dict):
        rule_applied, _rule_errors = apply_rules(app, saved["rules"])
        applied.extend(rule_applied)
    return applied'''

GET_OLD = '        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app)})'
GET_NEW = ('        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app),\n'
           '                             "rules": read_rules(request.app)})')

POST_OLD = '''        applied, errors = apply_settings(request.app, payload.get("values", {}))
        return JSONResponse({"applied": applied, "errors": errors,
                             "values": read_settings(request.app)})'''
POST_NEW = '''        applied, errors = apply_settings(request.app, payload.get("values", {}))
        rule_changes = payload.get("rules") or {}
        if rule_changes:
            rule_applied, rule_errors = apply_rules(request.app, rule_changes)
            applied.extend(rule_applied)
            errors.extend(rule_errors)
        return JSONResponse({"applied": applied, "errors": errors,
                             "values": read_settings(request.app),
                             "rules": read_rules(request.app)})'''

PERSIST_CALL_OLD = '''    if applied:
        persist_settings(merged)'''
PERSIST_CALL_NEW = '''    if applied:
        persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)})'''

HTML_OLD = '    <div id="settings-fields"></div>'
HTML_NEW = ('    <div id="settings-fields"></div>\n'
            '    <h2 class="sub" style="margin-top:18px;font-size:14px;">Правила политик</h2>\n'
            '    <div class="hint">Выключенное правило не участвует в решениях. Изменения применяются сразу.</div>\n'
            '    <div id="rules-fields"></div>')

JS_LOAD_OLD = "  SETTINGS_BOX.classList.add('open');"
JS_LOAD_NEW = '''  const rulesBox = document.getElementById('rules-fields');
  if (rulesBox) {
    rulesBox.innerHTML = '';
    for (const rule of (payload.rules || [])) {
      const row = document.createElement('div');
      row.className = 'field';
      row.innerHTML = '<div><div>' + (rule.title || rule.id) + '</div>' +
                      '<div class="key">' + rule.id + '</div></div>';
      const control = document.createElement('div');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = rule.enabled;
      input.dataset.rule = rule.id;
      control.appendChild(input);
      row.appendChild(control);
      rulesBox.appendChild(row);
    }
  }
  SETTINGS_BOX.classList.add('open');'''

JS_SAVE_OLD = '''  const response = await fetch('/ui/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({values})
  });'''
JS_SAVE_NEW = '''  const rules = {};
  for (const input of document.querySelectorAll('[data-rule]')) {
    rules[input.dataset.rule] = input.checked;
  }
  const response = await fetch('/ui/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({values, rules})
  });'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "apply_rules" in text:
        print("тумблеры уже есть")
        return 0
    pairs = [
        ("def read_settings(app: Any) -> dict[str, Any]:", HELPERS),
        (PERSIST_OLD, PERSIST_NEW),
        (RESTORE_OLD, RESTORE_NEW),
        (GET_OLD, GET_NEW),
        (POST_OLD, POST_NEW),
        (PERSIST_CALL_OLD, PERSIST_CALL_NEW),
        (HTML_OLD, HTML_NEW),
        (JS_LOAD_OLD, JS_LOAD_NEW),
        (JS_SAVE_OLD, JS_SAVE_NEW),
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

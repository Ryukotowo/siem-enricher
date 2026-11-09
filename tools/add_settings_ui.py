"""Страница настроек в панели: просмотр и изменение параметров на лету."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

CSS_ANCHOR = "  #detail { padding:0; }"
CSS_ADD = """  .settings-btn { margin-left:auto; }
  #settings { position:fixed; inset:0; background:rgba(8,16,40,.45); display:none;
              align-items:center; justify-content:center; z-index:50; }
  #settings.open { display:flex; }
  #settings .box { background:#fff; border-radius:12px; width:720px; max-height:84vh;
                   overflow:auto; padding:20px 22px; box-shadow:0 20px 60px rgba(8,16,40,.3); }
  #settings h2 { margin:0 0 4px; font-size:17px; }
  #settings .hint { color:var(--muted); font-size:12px; margin-bottom:14px; }
  .field { display:grid; grid-template-columns: 1fr 190px; gap:12px; align-items:center;
           padding:9px 0; border-bottom:1px solid #EEF1F6; }
  .field:last-of-type { border-bottom:0; }
  .field label { font-size:13px; }
  .field .key { color:var(--muted); font-size:11px; font-family:Consolas,monospace; }
  .field input[type=number] { width:100%; padding:6px 8px; border:1px solid var(--line);
                              border-radius:6px; font-size:13px; }
  .field select { width:100%; padding:6px 8px; border:1px solid var(--line); border-radius:6px;
                  font-size:13px; }
  .field input[type=checkbox] { width:18px; height:18px; }
  #settings .actions { display:flex; gap:10px; justify-content:flex-end; margin-top:16px; }
  #settings .actions button { border-radius:8px; padding:8px 16px; font-size:13px; cursor:pointer; }
  #settings .save { background:var(--accent); color:#fff; border:1px solid var(--accent); }
  #settings .cancel { background:#fff; color:#2B3442; border:1px solid var(--line); }
  #settings .result { font-size:12px; color:var(--muted); margin-top:10px; }
"""

BUTTON_ANCHOR = '      <button data-filter="secret">класс secret</button>'
BUTTON_ADD = BUTTON_ANCHOR + '\n      <button id="settings-open" class="settings-btn">настройки</button>'

MODAL_ANCHOR = "</main>"
MODAL_ADD = """</main>
<div id="settings">
  <div class="box">
    <h2>Параметры эксплуатации</h2>
    <div class="hint">Изменения применяются сразу, без перезапуска. Значения проверяются на допустимый диапазон.</div>
    <div id="settings-fields"></div>
    <div class="actions">
      <button class="cancel" id="settings-cancel">отмена</button>
      <button class="save" id="settings-save">применить</button>
    </div>
    <div class="result" id="settings-result"></div>
  </div>
</div>"""

JS_ANCHOR = "</script>"
JS_ADD = """
const SETTINGS_BOX = document.getElementById('settings');
const SETTINGS_FIELDS = document.getElementById('settings-fields');
const SETTINGS_RESULT = document.getElementById('settings-result');

async function openSettings() {
  SETTINGS_RESULT.textContent = '';
  const response = await fetch('/ui/config');
  const payload = await response.json();
  SETTINGS_FIELDS.innerHTML = '';
  for (const item of payload.settings) {
    const value = payload.values[item.key];
    const row = document.createElement('div');
    row.className = 'field';
    const label = document.createElement('div');
    label.innerHTML = '<div>' + item.label + '</div><div class="key">' + item.key + '</div>';
    const control = document.createElement('div');
    let input;
    if (item.type === 'bool') {
      input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = !!value;
    } else if (item.type === 'select') {
      input = document.createElement('select');
      for (const option of item.options) {
        const node = document.createElement('option');
        node.value = option; node.textContent = option;
        if (option === value) node.selected = true;
        input.appendChild(node);
      }
    } else {
      input = document.createElement('input');
      input.type = 'number';
      input.min = item.min; input.max = item.max; input.step = item.step;
      input.value = value;
    }
    input.dataset.key = item.key;
    input.dataset.kind = item.type;
    control.appendChild(input);
    row.appendChild(label); row.appendChild(control);
    SETTINGS_FIELDS.appendChild(row);
  }
  SETTINGS_BOX.classList.add('open');
}

async function saveSettings() {
  const values = {};
  for (const input of SETTINGS_FIELDS.querySelectorAll('[data-key]')) {
    const kind = input.dataset.kind;
    values[input.dataset.key] = kind === 'bool' ? input.checked
                              : kind === 'number' ? Number(input.value)
                              : input.value;
  }
  const response = await fetch('/ui/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({values})
  });
  const payload = await response.json();
  if (payload.errors && payload.errors.length) {
    SETTINGS_RESULT.textContent = 'не применено: ' + payload.errors.join('; ');
  } else {
    SETTINGS_RESULT.textContent = 'применено: ' + payload.applied.join(', ');
    setTimeout(() => SETTINGS_BOX.classList.remove('open'), 900);
  }
}

document.getElementById('settings-open').addEventListener('click', openSettings);
document.getElementById('settings-cancel').addEventListener('click',
  () => SETTINGS_BOX.classList.remove('open'));
document.getElementById('settings-save').addEventListener('click', saveSettings);
</script>"""

PY_ANCHOR = "def register_panel(app: Any, buffer: EventBuffer) -> bool:"
PY_ADD = '''SETTINGS_SCHEMA = [
    {"key": "risk.medium", "label": "Порог риска «средний»", "type": "number",
     "min": 0.05, "max": 0.6, "step": 0.05},
    {"key": "risk.high", "label": "Порог риска «высокий»", "type": "number",
     "min": 0.2, "max": 0.9, "step": 0.05},
    {"key": "risk.critical", "label": "Порог риска «критический»", "type": "number",
     "min": 0.4, "max": 1.0, "step": 0.05},
    {"key": "policy.mode", "label": "Режим политик", "type": "select",
     "options": ["dry_run", "live"]},
    {"key": "policy.stop_on_block", "label": "Останавливаться на блокировке", "type": "bool"},
    {"key": "provenance.max_edges_per_path", "label": "Рёбер на путь (окно истории)",
     "type": "number", "min": 8, "max": 400, "step": 8},
    {"key": "provenance.edge_limit", "label": "Лимит рёбер на шаг обхода",
     "type": "number", "min": 20, "max": 400, "step": 10},
    {"key": "ml.cache_size", "label": "Кэш классификации по имени",
     "type": "number", "min": 0, "max": 65536, "step": 512},
    {"key": "runtime.batch_size", "label": "Размер пачки обработки",
     "type": "number", "min": 1, "max": 256, "step": 1},
]


def _pipeline_of(app: Any) -> Any:
    runtime = getattr(app.state, "runtime", None)
    pipeline = getattr(runtime, "pipeline", None)
    if pipeline is None:
        pipeline = getattr(app.state, "pipeline", None)
    return pipeline


def read_settings(app: Any) -> dict[str, Any]:
    """Текущие значения параметров, доступных для изменения через панель."""
    import os

    pipeline = _pipeline_of(app)
    values: dict[str, Any] = {}
    if pipeline is None:
        return values
    thresholds = getattr(getattr(pipeline, "scorer", None), "thresholds", {}) or {}
    values["risk.medium"] = round(float(thresholds.get("medium", 0.3)), 3)
    values["risk.high"] = round(float(thresholds.get("high", 0.6)), 3)
    values["risk.critical"] = round(float(thresholds.get("critical", 0.85)), 3)
    engine = getattr(pipeline, "policy_engine", None)
    values["policy.mode"] = getattr(engine, "mode", "dry_run")
    values["policy.stop_on_block"] = bool(getattr(engine, "stop_on_block", True))
    values["provenance.max_edges_per_path"] = int(getattr(pipeline, "max_edges_per_path", 64))
    values["provenance.edge_limit"] = int(getattr(pipeline, "edge_limit", 120))
    values["ml.cache_size"] = int(getattr(getattr(pipeline, "classifier", None), "max_entries", 0) or 0)
    values["runtime.batch_size"] = int(os.environ.get("SIEM_BATCH_SIZE", "64"))
    return values


def apply_settings(app: Any, payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Применить изменения на лету; вернуть списки применённых ключей и ошибок."""
    import os

    pipeline = _pipeline_of(app)
    applied: list[str] = []
    errors: list[str] = []
    if pipeline is None:
        return applied, ["сервис не запущен в режиме обработки"]

    current = read_settings(app)
    merged = dict(current)
    merged.update({key: value for key, value in (payload or {}).items() if key in current})

    try:
        medium = float(merged["risk.medium"])
        high = float(merged["risk.high"])
        critical = float(merged["risk.critical"])
    except (TypeError, ValueError):
        return applied, ["пороги риска должны быть числами"]
    if not (medium < high < critical):
        return applied, ["пороги должны возрастать: средний < высокий < критический"]

    try:
        thresholds = pipeline.scorer.thresholds
        thresholds["medium"], thresholds["high"], thresholds["critical"] = medium, high, critical
        applied.extend(["risk.medium", "risk.high", "risk.critical"])
    except Exception as exc:  # noqa: BLE001
        errors.append(f"пороги: {exc}")

    mode = str(merged.get("policy.mode", "dry_run"))
    if mode not in {"dry_run", "live"}:
        errors.append("режим политик: допустимо dry_run или live")
    else:
        engine = getattr(pipeline, "policy_engine", None)
        if engine is not None:
            engine.mode = mode
            engine.stop_on_block = bool(merged.get("policy.stop_on_block", True))
            applied.extend(["policy.mode", "policy.stop_on_block"])

    try:
        pipeline.max_edges_per_path = max(8, int(merged.get("provenance.max_edges_per_path", 64)))
        pipeline.edge_limit = max(20, int(merged.get("provenance.edge_limit", 120)))
        applied.extend(["provenance.max_edges_per_path", "provenance.edge_limit"])
    except (TypeError, ValueError):
        errors.append("параметры происхождения должны быть целыми")

    classifier = getattr(pipeline, "classifier", None)
    if classifier is not None and hasattr(classifier, "max_entries"):
        try:
            classifier.max_entries = max(0, int(merged.get("ml.cache_size", 0)))
            applied.append("ml.cache_size")
        except (TypeError, ValueError):
            errors.append("размер кэша должен быть целым")

    try:
        os.environ["SIEM_BATCH_SIZE"] = str(max(1, int(merged.get("runtime.batch_size", 64))))
        applied.append("runtime.batch_size")
    except (TypeError, ValueError):
        errors.append("размер пачки должен быть целым")

    return applied, errors


'''

ROUTES = '''    @app.get("/ui/config", include_in_schema=False)
    async def panel_config(request: Request) -> Any:
        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app)})

    @app.post("/ui/config", include_in_schema=False)
    async def panel_config_save(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"applied": [], "errors": ["некорректный JSON"]}, status_code=400)
        applied, errors = apply_settings(request.app, payload.get("values", {}))
        return JSONResponse({"applied": applied, "errors": errors,
                             "values": read_settings(request.app)})

    return True'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "SETTINGS_SCHEMA" in text:
        print("настройки уже есть")
        return 0
    pairs = [
        (CSS_ANCHOR, CSS_ADD + CSS_ANCHOR),
        (BUTTON_ANCHOR, BUTTON_ADD),
        (MODAL_ANCHOR, MODAL_ADD),
        (JS_ANCHOR, JS_ADD),
        (PY_ANCHOR, PY_ADD + PY_ANCHOR),
        ("    return True\n\n\n__all__", ROUTES + "\n\n\n__all__"),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:46]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

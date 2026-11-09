"""Панель аналитика: обогащённые события, класс, риск и решение.

Модуль не зависит от FastAPI: здесь только модель данных и HTML.
Подключение к HTTP-сервису — в конце файла (register_panel).
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Iterable

PANEL_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Обогащение событий SIEM</title>
<style>
  :root { --navy:#050D3F; --accent:#1F5FC0; --line:#DCE3EE; --muted:#5B6470;
          --crit:#B3261E; --high:#C26A00; --med:#1F5FC0; --low:#5B6470; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:"Segoe UI", Arial, sans-serif; color:#14181D; background:#F4F6FA; }
  header { background:var(--navy); color:#fff; padding:16px 24px; display:flex;
           align-items:center; justify-content:space-between; }
  header h1 { margin:0; font-size:19px; font-weight:600; letter-spacing:.2px; }
  header .stats { display:flex; gap:22px; font-size:13px; color:#C7D2E5; }
  header .stats b { color:#fff; font-size:16px; display:block; }
  main { display:grid; grid-template-columns: 1fr 420px; gap:16px; padding:16px 24px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  .toolbar { display:flex; gap:8px; padding:12px 14px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  .toolbar button { border:1px solid var(--line); background:#fff; border-radius:7px; padding:6px 12px;
                    font-size:13px; cursor:pointer; color:#2B3442; }
  .toolbar button.active { background:var(--accent); border-color:var(--accent); color:#fff; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; font-weight:600; color:var(--muted); padding:9px 12px;
       border-bottom:1px solid var(--line); background:#FAFBFD; white-space:nowrap; }
  td { padding:8px 12px; border-bottom:1px solid #EEF1F6; vertical-align:middle; }
  tbody tr { cursor:pointer; }
  tbody tr:hover { background:#F3F7FF; }
  tbody tr.sel { background:#E8F0FE; }
  .file { font-weight:600; }
  .path { color:var(--muted); font-size:12px; }
  .badge { display:inline-block; padding:2px 9px; border-radius:20px; font-size:12px; font-weight:600; }
  .b-secret { background:#FBE4E2; color:var(--crit); }
  .b-confidential { background:#FDF0E0; color:var(--high); }
  .b-internal { background:#E6EEF9; color:var(--accent); }
  .b-public { background:#E7F2E9; color:#2E7D32; }
  .b-unknown { background:#EEF0F3; color:var(--muted); }
  .d-block { background:var(--crit); color:#fff; }
  .d-mask { background:var(--high); color:#fff; }
  .d-alert { background:#FDF0E0; color:var(--high); }
  .d-tag { background:#EEF0F3; color:#2B3442; }
  .d-allow { background:#E7F2E9; color:#2E7D32; }
  .risk { display:flex; align-items:center; gap:8px; white-space:nowrap; }
  .bar { width:64px; height:6px; border-radius:3px; background:#E9EDF3; overflow:hidden; }
  .bar span { display:block; height:100%; }
  .num { font-variant-numeric: tabular-nums; }
  .settings-btn { margin-left:auto; }
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
  #detail { padding:0; }
  #detail .head { padding:14px 16px; border-bottom:1px solid var(--line); background:#FAFBFD; }
  #detail .head h2 { margin:0 0 4px; font-size:15px; }
  #detail .body { padding:14px 16px; max-height:74vh; overflow:auto; }
  .row { margin-bottom:12px; }
  .row .k { color:var(--muted); font-size:12px; margin-bottom:2px; }
  .row .v { font-size:13px; line-height:1.45; }
  .chip { display:inline-block; background:#E6EEF9; color:var(--accent); border-radius:6px;
          padding:1px 7px; margin:0 4px 4px 0; font-size:12px; }
  .empty { padding:40px 16px; text-align:center; color:var(--muted); font-size:13px; }
  code { background:#F1F3F7; border-radius:4px; padding:1px 5px; font-size:12px; }
  .hash { display:inline-block; background:#EEF0F3; color:#5B6470; border-radius:4px;
          padding:0 6px; font-size:11px; margin-left:6px; }
  .chain-btn { border:1px solid var(--line); background:#fff; border-radius:7px; padding:5px 11px;
               font-size:12px; cursor:pointer; color:var(--accent); }
  .chain { margin-top:8px; border-left:2px solid #DCE3EE; padding-left:10px; display:none; }
  .chain.open { display:block; }
  .chain .step { font-size:12px; margin-bottom:6px; color:#2B3442; }
  .chain .step b { color:var(--navy); }
  .chain .step span { color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>Обогащение событий SIEM — панель аналитика</h1>
  <div class="stats">
    <div><b id="c-total">0</b>событий</div>
    <div><b id="c-crit">0</b>критичных</div>
    <div><b id="c-block">0</b>решений о блокировке</div>
    <div><b id="c-fp">0</b>открытых файлов</div>
  </div>
</header>
<main>
  <section class="card">
    <div class="toolbar">
      <button data-filter="all" class="active">все события</button>
      <button data-filter="block">блокировка</button>
      <button data-filter="mask">маскирование</button>
      <button data-filter="high">риск высокий и выше</button>
      <button data-filter="secret">класс secret</button>
      <button id="settings-open" class="settings-btn">настройки</button>
    </div>
    <table>
      <thead>
      <tr><th>Время</th><th>Файл</th><th>Действие</th><th>Класс</th><th>Уверенность</th>
          <th>Риск</th><th>Решение</th><th>Правило</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    <div id="empty" class="empty">данных пока нет — отправьте событие в сервис</div>
  </section>
  <aside class="card" id="detail">
    <div class="head"><h2>Выберите событие</h2><div class="path">здесь появится обоснование решения</div></div>
    <div class="body" id="detail-body"></div>
  </aside>
</main>
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
</div>
<script>
let DATA = [], FILTER = 'all', SELECTED = null;

function badgeClass(level) {
  return 'badge b-' + (level || 'unknown');
}
function decisionClass(decision) {
  return 'badge d-' + (decision || 'allow');
}
function severityColor(severity) {
  return severity === 'critical' ? '#B3261E' : severity === 'high' ? '#C26A00'
       : severity === 'medium' ? '#1F5FC0' : '#5B6470';
}
function matches(event) {
  if (FILTER === 'all') return true;
  if (FILTER === 'block' || FILTER === 'mask') return event.decision === FILTER;
  if (FILTER === 'high') return ['high', 'critical'].includes(event.severity);
  if (FILTER === 'secret') return event.sensitivity === 'secret';
  return true;
}
function fmt(value) {
  return (value === null || value === undefined) ? '—' : value;
}
function render() {
  const rows = DATA.filter(matches);
  const body = document.getElementById('rows');
  document.getElementById('empty').style.display = rows.length ? 'none' : 'block';
  document.getElementById('c-total').textContent = DATA.length;
  document.getElementById('c-crit').textContent = DATA.filter(e => e.severity === 'critical').length;
  document.getElementById('c-block').textContent = DATA.filter(e => e.decision === 'block').length;
  document.getElementById('c-fp').textContent = DATA.filter(e => e.sensitivity === 'public').length;
  body.innerHTML = rows.map((e, index) => {
    const risk = Math.max(0, Math.min(1, e.risk || 0));
    const color = severityColor(e.severity);
    return `<tr data-id="${e.event_id}" class="${SELECTED === e.event_id ? 'sel' : ''}">
      <td class="num">${(e.ts || '').slice(11, 19)}</td>
      <td><div class="file">${e.file || '—'}${e.hash_only ? ' <span class="hash" title="имя пришло хэшем, полного имени в событии нет">хэш</span>' : ''}</div><div class="path">${e.directory || ''}</div></td>
      <td>${e.action || ''}</td>
      <td><span class="${badgeClass(e.sensitivity)}">${e.sensitivity_ru || e.sensitivity || '—'}</span></td>
      <td class="num">${e.confidence ? e.confidence.toFixed(2) : '—'}</td>
      <td><div class="risk"><div class="bar"><span style="width:${risk * 100}%;background:${color}"></span></div>
          <span class="num" style="color:${color}">${risk.toFixed(2)}</span></div></td>
      <td><span class="${decisionClass(e.decision)}">${e.decision || 'allow'}</span></td>
      <td>${(e.rules || []).join(', ') || '—'}</td>
    </tr>`;
  }).join('');
  body.querySelectorAll('tr').forEach(row => row.addEventListener('click', () => select(row.dataset.id)));
}
function toggleChain(button) {
  const chain = button.parentElement.querySelector('.chain');
  const open = chain.classList.toggle('open');
  button.textContent = open ? 'скрыть цепочку' : 'показать цепочку';
}
function select(eventId) {
  SELECTED = eventId;
  const event = DATA.find(item => item.event_id === eventId);
  render();
  if (!event) return;
  const components = Object.entries(event.components || {})
    .map(([key, value]) => `<span class="chip">${key}: ${typeof value === 'number' ? value.toFixed(3) : value}</span>`)
    .join('');
  document.getElementById('detail').querySelector('.head').innerHTML =
    `<h2>${event.file || '—'}</h2><div class="path">${event.path || ''}</div>`;
  document.getElementById('detail-body').innerHTML = `
    <div class="row"><div class="k">класс конфиденциальности</div>
      <div class="v"><span class="${badgeClass(event.sensitivity)}">${event.sensitivity_ru || event.sensitivity}</span>
      &nbsp;уверенность ${event.confidence ? event.confidence.toFixed(2) : '—'} · метод ${event.method || '—'}</div></div>
    <div class="row"><div class="k">почему такой класс</div><div class="v">${event.reason || '—'}</div></div>
    <div class="row"><div class="k">риск</div><div class="v">
      <b style="color:${severityColor(event.severity)}">${(event.risk || 0).toFixed(2)} · ${event.severity || '—'}</b>
      &nbsp;внешних адресатов: ${fmt(event.external)} · глубина цепочки: ${fmt(event.depth)}</div>
      <div style="margin-top:6px">${components}</div></div>
    <div class="row"><div class="k">решение</div><div class="v">
      <span class="${decisionClass(event.decision)}">${event.decision || 'allow'}</span>
      ${(event.rules || []).map(r => `<span class="chip">${r}</span>`).join('')}</div></div>
    <div class="row"><div class="k">происхождение</div>
      <button class="chain-btn" onclick="toggleChain(this)">показать цепочку (${(event.steps || []).length})</button>
      <div class="chain">${
        (event.steps || []).map((step, index) =>
          `<div class="step"><b>${index + 1}. ${step.action || '—'}</b> ${step.endpoint ? '→ ' + step.endpoint : ''}
           <br><span>${(step.ts || '').replace('T', ' ').slice(0, 19)} · ${step.actor || '—'}${step.direction ? ' · ' + step.direction : ''}</span></div>`
        ).join('') || '<div class="step"><span>шагов нет</span></div>'
      }${(event.endpoints || []).length ? `<div class="step"><span>внешние адреса: ${event.endpoints.join(', ')}</span></div>` : ''}</div></div>
    <div class="row"><div class="k">идентификатор события</div><div class="v"><code>${event.event_id}</code></div></div>`;
}
async function loadEvents() {
  for (const url of ['/api/events', '/ui/events']) {
    try {
      const response = await fetch(url, { cache: 'no-store' });
      if (response.ok) return await response.json();
    } catch (error) { /* пробуем следующий адрес */ }
  }
  return { events: [] };
}
async function refresh() {
  try {
    const payload = await loadEvents();
    DATA = payload.events || [];
    if (!SELECTED) {
      const first = DATA.find(item => item.decision === 'block') || DATA[0];
      if (first) { select(first.event_id); return; }
    }
    render();
  } catch (error) { /* сервис ещё не поднят */ }
}
document.querySelectorAll('.toolbar button').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.toolbar button').forEach(item => item.classList.remove('active'));
    button.classList.add('active');
    FILTER = button.dataset.filter;
    render();
  });
});
refresh();
setInterval(refresh, 2000);

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
if (new URLSearchParams(location.search).has('settings')) { openSettings(); }
document.getElementById('settings-cancel').addEventListener('click',
  () => SETTINGS_BOX.classList.remove('open'));
document.getElementById('settings-save').addEventListener('click', saveSettings);
</script>
</body>
</html>
"""

COMPACT_FIELDS = (
    "event_id", "ts", "action", "file", "path", "directory", "sensitivity",
    "sensitivity_ru", "confidence", "method", "reason", "risk", "severity",
    "decision", "rules", "depth", "external", "removable", "components",
)


def _clean_name(name: str | None, path: str | None) -> str:
    """Имя файла для показа: хэши и служебные строки не выдаём за имя файла."""
    name = (name or "").strip()
    if not name or name.lower().startswith("sha256:"):
        path = (path or "").strip()
        if path and not path.lower().startswith("sha256:"):
            return path.replace("\\\\", "/").rsplit("/", 1)[-1]
        return "(файл по хэшу)"
    return name


def _hash_only(file_info: dict[str, Any]) -> bool:
    """Имя файла пришло хэшем — объект известен только по отпечатку."""
    name = str(file_info.get("name") or "").strip().lower()
    path = str(file_info.get("path") or "").strip().lower()
    return name.startswith("sha256:") or (not name and path.startswith("sha256:"))


def _chains_dict(document: dict[str, Any]) -> dict[str, Any]:
    """Цепочка происхождения: в документе это объект или список объектов."""
    chains = document.get("provenance_chains")
    if isinstance(chains, list):
        return chains[0] if chains and isinstance(chains[0], dict) else {}
    return chains if isinstance(chains, dict) else {}


def _chain_steps(document: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """Шаги цепочки происхождения для карточки события."""
    chains = _chains_dict(document)
    raw = chains.get("steps")
    if not raw:
        single = document.get("provenance_chain")
        raw = [single] if isinstance(single, dict) else []
    steps: list[dict[str, Any]] = []
    for item in (raw or [])[:limit]:
        if not isinstance(item, dict):
            continue
        steps.append({
            "ts": item.get("timestamp") or "",
            "action": item.get("action") or "",
            "actor": item.get("actor_process") or item.get("actor_user") or "",
            "endpoint": item.get("endpoint") or "",
            "direction": item.get("direction") or "",
            "path": item.get("path") or "",
        })
    return steps


def compact(document: dict[str, Any]) -> dict[str, Any]:
    """Свести обогащённый документ к полям, которые нужны панели."""
    file_info = document.get("file") or {}
    return {
        "event_id": document.get("event_id"),
        "ts": document.get("@timestamp") or document.get("timestamp") or "",
        "action": document.get("action"),
        "file": _clean_name(file_info.get("name"), file_info.get("path")),
        "path": file_info.get("path") or "",
        "directory": file_info.get("directory") or "",
        "sensitivity": document.get("data_sensitivity"),
        "sensitivity_ru": document.get("data_sensitivity_ru"),
        "confidence": document.get("sensitivity_confidence"),
        "method": document.get("sensitivity_method"),
        "reason": document.get("sensitivity_reason"),
        "risk": document.get("risk_score"),
        "severity": document.get("risk_severity"),
        "decision": document.get("policy_decision"),
        "rules": list(document.get("policy_rule_ids") or []),
        "depth": document.get("provenance_depth"),
        "external": document.get("external_destinations_count"),
        "removable": document.get("removable_destinations_count"),
        "components": document.get("risk_components") or {},
        "hash_only": _hash_only(file_info),
        "steps": _chain_steps(document),
        "endpoints": list(_chains_dict(document).get("external_endpoints") or [])[:6],
    }


class EventBuffer:
    """Кольцевой буфер последних обогащённых событий."""

    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)

    def add(self, document: dict[str, Any]) -> None:
        record = compact(document)
        if record.get("event_id"):
            self._items = deque((i for i in self._items if i.get("event_id") != record["event_id"]),
                                maxlen=self._items.maxlen)
        self._items.append(record)

    def extend(self, documents: Iterable[dict[str, Any]]) -> None:
        for document in documents:
            self.add(document)

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        items = list(self._items)[-limit:]
        return list(reversed(items))

    def stats(self) -> dict[str, Any]:
        items = list(self._items)
        return {
            "total": len(items),
            "critical": sum(1 for item in items if item.get("severity") == "critical"),
            "blocked": sum(1 for item in items if item.get("decision") == "block"),
        }


def load_documents(path: Path) -> list[dict[str, Any]]:
    """Прочитать обогащённые документы из JSONL."""
    if not path.exists():
        return []
    documents = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return documents


SETTINGS_SCHEMA = [
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


def register_panel(app: Any, buffer: EventBuffer) -> bool:
    """Подключить панель к приложению FastAPI (если он установлен)."""
    try:
        from fastapi import Request
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError:  # pragma: no cover - FastAPI необязателен
        return False

    globals()['Request'] = Request
    app.state.panel_buffer = buffer

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    async def panel_page() -> Any:
        return HTMLResponse(PANEL_HTML)

    @app.get("/ui/events", include_in_schema=False)
    async def panel_events(request: Request, limit: int = 200) -> Any:
        store: EventBuffer = request.app.state.panel_buffer
        return JSONResponse({"events": store.recent(limit), "stats": store.stats()})

    @app.get("/ui/config", include_in_schema=False)
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

    return True


__all__ = ["PANEL_HTML", "EventBuffer", "compact", "load_documents", "register_panel", "COMPACT_FIELDS"]

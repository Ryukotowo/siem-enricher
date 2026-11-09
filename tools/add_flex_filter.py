"""Гибкий фильтр, сортировка, экспорт и тёмная тема в панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

CSS = """  .filters { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:10px 14px;
             border-bottom:1px solid var(--line); background:#FCFDFF; }
  .filters input[type=search] { flex:1 1 260px; min-width:200px; padding:7px 10px; font-size:13px;
             border:1px solid var(--line); border-radius:8px; }
  .filters select { padding:7px 8px; font-size:13px; border:1px solid var(--line); border-radius:8px; }
  .filters .grp { display:flex; gap:4px; }
  .filters .grp button { border:1px solid var(--line); background:#fff; border-radius:7px;
             padding:5px 9px; font-size:12px; cursor:pointer; color:#2B3442; }
  .filters .grp button.on { background:var(--navy); border-color:var(--navy); color:#fff; }
  .filters .riskbox { display:flex; align-items:center; gap:7px; font-size:12px; color:var(--muted); }
  .filters .riskbox input { width:98px; }
  .filters .riskbox b { color:var(--navy); font-size:12px; min-width:26px; }
  .filters .ghost { border:1px solid var(--line); background:#fff; border-radius:7px; padding:6px 11px;
             font-size:12px; cursor:pointer; color:#2B3442; }
  .filters .ghost:hover { border-color:var(--accent); color:var(--accent); }
  .filters .counter { margin-left:auto; font-size:12px; color:var(--muted); }
  th[data-sort] { cursor:pointer; user-select:none; }
  th[data-sort]:hover { color:var(--accent); }
  th .arrow { font-size:10px; color:var(--accent); }
  body.dark { background:#111823; }
  body.dark .card, body.dark header { background:#1B2432; border-color:#2A3546; }
  body.dark header { background:#0C1424; }
  body.dark td, body.dark th { border-color:#26303F; color:#DCE3EE; }
  body.dark th { background:#202B3B; }
  body.dark tbody tr:hover { background:#22303F; }
  body.dark tbody tr.sel { background:#243A57; }
  body.dark .filters { background:#18212E; border-color:#26303F; }
  body.dark .filters input[type=search], body.dark .filters select, body.dark .filters .grp button,
  body.dark .filters .ghost { background:#1B2432; color:#DCE3EE; border-color:#2A3546; }
  body.dark #detail .head { background:#202B3B; border-color:#26303F; }
  body.dark .path, body.dark .key { color:#8C99AC; }
</style>"""

TOOLBAR_OLD = '''    <div class="toolbar">
      <button data-filter="all" class="active">все события</button>
      <button data-filter="block">блокировка</button>
      <button data-filter="mask">маскирование</button>
      <button data-filter="high">риск высокий и выше</button>
      <button data-filter="secret">класс secret</button>
      <button id="settings-open" class="settings-btn">настройки</button>
    </div>'''

TOOLBAR_NEW = '''    <div class="filters">
      <input id="q" type="search" placeholder="поиск: файл, каталог, правило, id события">
      <div class="grp" id="dec-chips">
        <button data-dec="block">block</button><button data-dec="mask">mask</button>
        <button data-dec="tag">tag</button><button data-dec="allow">allow</button>
      </div>
      <div class="grp" id="cls-chips">
        <button data-cls="secret">secret</button><button data-cls="confidential">confidential</button>
        <button data-cls="internal">internal</button><button data-cls="public">public</button>
      </div>
      <select id="action-sel">
        <option value="">любое действие</option>
      </select>
      <label class="riskbox">риск ≥ <input id="risk-min" type="range" min="0" max="1" step="0.05" value="0"><b id="risk-min-v">0.00</b></label>
      <button class="ghost" id="reset">сбросить</button>
      <button class="ghost" id="export">CSV</button>
      <button class="ghost" id="theme">тема</button>
      <button id="settings-open">настройки</button>
      <span class="counter" id="counter"></span>
    </div>'''

THEAD_OLD = '''      <tr><th>Время</th><th>Файл</th><th>Действие</th><th>Класс</th><th>Уверенность</th>
          <th>Риск</th><th>Решение</th><th>Правило</th></tr>'''
THEAD_NEW = '''      <tr><th data-sort="ts">Время</th><th data-sort="file">Файл</th>
          <th data-sort="action">Действие</th><th data-sort="sensitivity">Класс</th>
          <th data-sort="confidence">Уверенность</th><th data-sort="risk">Риск</th>
          <th data-sort="decision">Решение</th><th data-sort="rule">Правило</th></tr>'''

STATE_OLD = "let DATA = [], FILTER = 'all', SELECTED = null;"
STATE_NEW = """let DATA = [], SELECTED = null;
let FILTERS = {q: '', decisions: new Set(), classes: new Set(), action: '', riskMin: 0};
let SORT = {key: 'ts', dir: -1};

function matches(event) {
  const q = FILTERS.q.trim().toLowerCase();
  if (q) {
    const haystack = [event.file, event.directory, (event.rules || []).join(' '),
                      event.event_id, event.action].join(' ').toLowerCase();
    if (!haystack.includes(q)) return false;
  }
  if (FILTERS.decisions.size && !FILTERS.decisions.has(event.decision)) return false;
  if (FILTERS.classes.size && !FILTERS.classes.has(event.sensitivity)) return false;
  if (FILTERS.action && event.action !== FILTERS.action) return false;
  if ((event.risk || 0) < FILTERS.riskMin) return false;
  return true;
}

function sortValue(event, key) {
  if (key === 'ts') return event.ts || '';
  if (key === 'rule') return (event.rules || []).join(',');
  if (key === 'risk') return event.risk || 0;
  if (key === 'confidence') return event.confidence || 0;
  if (key === 'sensitivity') return event.sensitivity || '';
  return (event[key] || '').toString().toLowerCase();
}

function visibleRows() {
  const rows = DATA.filter(matches);
  rows.sort((a, b) => {
    const left = sortValue(a, SORT.key), right = sortValue(b, SORT.key);
    if (left === right) return 0;
    return (left > right ? 1 : -1) * SORT.dir;
  });
  return rows;
}

function refreshActions() {
  const select = document.getElementById('action-sel');
  if (!select || select.dataset.filled) return;
  const actions = Array.from(new Set(DATA.map(e => e.action).filter(Boolean))).sort();
  for (const action of actions) {
    const option = document.createElement('option');
    option.value = action; option.textContent = action;
    select.appendChild(option);
  }
  select.dataset.filled = '1';
}

function exportCsv() {
  const rows = visibleRows();
  const header = ['время', 'файл', 'каталог', 'действие', 'класс', 'уверенность',
                  'риск', 'уровень', 'решение', 'правила', 'id'];
  const lines = [header.join(';')];
  for (const e of rows) {
    lines.push([e.ts || '', e.file || '', e.directory || '', e.action || '', e.sensitivity || '',
                e.confidence ?? '', (e.risk || 0).toFixed(2), e.severity || '', e.decision || '',
                (e.rules || []).join(' '), e.event_id || '']
               .map(value => String(value).replaceAll(';', ',')).join(';'));
  }
  const blob = new Blob(['\\ufeff' + lines.join('\\n')], {type: 'text/csv;charset=utf-8'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'siem-events.csv';
  link.click();
  URL.revokeObjectURL(link.href);
}"""

MATCHES_OLD = """function matches(event) {
  if (FILTER === 'all') return true;
  if (FILTER === 'block' || FILTER === 'mask') return event.decision === FILTER;
  if (FILTER === 'high') return ['high', 'critical'].includes(event.severity);
  if (FILTER === 'secret') return event.sensitivity === 'secret';
  return true;
}
"""

RENDER_OLD = """function render() {
  const rows = DATA.filter(matches);"""
RENDER_NEW = """function render() {
  refreshActions();
  const rows = visibleRows();"""

COUNTER_OLD = """  document.getElementById('c-fp').textContent = DATA.filter(e => e.sensitivity === 'public').length;"""
COUNTER_NEW = """  document.getElementById('c-fp').textContent = DATA.filter(e => e.sensitivity === 'public').length;
  const counter = document.getElementById('counter');
  if (counter) counter.textContent = `показано ${rows.length} из ${DATA.length}`;
  document.querySelectorAll('th[data-sort]').forEach(th => {
    const arrow = th.dataset.sort === SORT.key ? (SORT.dir > 0 ? ' ▲' : ' ▼') : '';
    th.innerHTML = th.textContent.replace(/[ ▲▼]+$/, '') + arrow;
  });"""

WIRING_ANCHOR = "if (new URLSearchParams(location.search).has('settings')) { openSettings(); }"
WIRING = WIRING_ANCHOR + """

const search = document.getElementById('q');
if (search) {
  search.addEventListener('input', () => { FILTERS.q = search.value; render(); });
}
for (const chip of document.querySelectorAll('#dec-chips button')) {
  chip.addEventListener('click', () => {
    const value = chip.dataset.dec;
    chip.classList.toggle('on');
    FILTERS.decisions.has(value) ? FILTERS.decisions.delete(value) : FILTERS.decisions.add(value);
    render();
  });
}
for (const chip of document.querySelectorAll('#cls-chips button')) {
  chip.addEventListener('click', () => {
    const value = chip.dataset.cls;
    chip.classList.toggle('on');
    FILTERS.classes.has(value) ? FILTERS.classes.delete(value) : FILTERS.classes.add(value);
    render();
  });
}
const riskRange = document.getElementById('risk-min');
if (riskRange) {
  riskRange.addEventListener('input', () => {
    FILTERS.riskMin = Number(riskRange.value);
    document.getElementById('risk-min-v').textContent = FILTERS.riskMin.toFixed(2);
    render();
  });
}
const actionSelect = document.getElementById('action-sel');
if (actionSelect) {
  actionSelect.addEventListener('change', () => { FILTERS.action = actionSelect.value; render(); });
}
const reset = document.getElementById('reset');
if (reset) {
  reset.addEventListener('click', () => {
    FILTERS = {q: '', decisions: new Set(), classes: new Set(), action: '', riskMin: 0};
    search.value = '';
    riskRange.value = '0';
    document.getElementById('risk-min-v').textContent = '0.00';
    actionSelect.value = '';
    document.querySelectorAll('#dec-chips button, #cls-chips button')
      .forEach(chip => chip.classList.remove('on'));
    render();
  });
}
const exportBtn = document.getElementById('export');
if (exportBtn) exportBtn.addEventListener('click', exportCsv);
const themeBtn = document.getElementById('theme');
if (themeBtn) {
  themeBtn.addEventListener('click', () => document.body.classList.toggle('dark'));
}
for (const th of document.querySelectorAll('th[data-sort]')) {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    SORT = {key, dir: SORT.key === key ? -SORT.dir : -1};
    render();
  });
}"""


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "FILTERS" in text:
        print("гибкий фильтр уже есть")
        return 0

    checks = [
        (TOOLBAR_OLD, TOOLBAR_NEW, "панель фильтров"),
        (THEAD_OLD, THEAD_NEW, "сортировка в шапке"),
        (STATE_OLD, STATE_NEW, "состояние фильтра"),
        (MATCHES_OLD, "", "старый matches"),
        (RENDER_OLD, RENDER_NEW, "рендер"),
        (COUNTER_OLD, COUNTER_NEW, "счётчик"),
        (WIRING_ANCHOR, WIRING, "обработчики"),
    ]
    for old, new, label in checks:
        if old not in text:
            print(f"!! не найдено: {label}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {label}")

    if CSS not in text:
        text = text.replace("</style>", CSS, 1)
        print("патч: стили")

    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

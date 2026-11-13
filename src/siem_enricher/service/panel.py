"""Панель аналитика: обогащённые события, класс, риск и решение.

Модуль не зависит от FastAPI: здесь только модель данных и HTML.
Подключение к HTTP-сервису — в конце файла (register_panel).
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any

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
  header .theme { align-self:center; margin-left:8px; padding:6px 10px; font-size:12px;
    background:rgba(255,255,255,.12); color:#fff; border:1px solid rgba(255,255,255,.28);
    border-radius:6px; cursor:pointer; }
  header .theme:hover { background:rgba(255,255,255,.2); }

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
  .audit { font-size:12px; color:#2B3442; max-height:150px; overflow:auto; }
  .audit .item { padding:5px 0; border-bottom:1px solid #EEF1F6; display:flex;
                 justify-content:space-between; gap:10px; }
  .audit .item span { color:var(--muted); white-space:nowrap; }
  body.dark .audit { color:#DCE3EE; }
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
  .filters { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:10px 14px;
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
  .live { display:inline-flex; align-items:center; gap:7px; font-size:12px; color:#C7D2E5;
          margin-right:6px; }
  .live i { width:8px; height:8px; border-radius:50%; background:#3DDC84; display:inline-block;
            animation:pulse 1.6s infinite; }
  .live.off i { background:#B3261E; animation:none; }
  .live.paused i { background:#F0A500; animation:none; }
  @keyframes pulse { 0%{opacity:.35} 50%{opacity:1} 100%{opacity:.35} }
  .pending { color:#F0A500; font-size:12px; }
  .dash { display:grid; grid-template-columns: 1.4fr 1fr 1fr 1fr; gap:12px; grid-column:1 / -1; }
  .dash .box { background:#fff; border:1px solid var(--line); border-radius:10px; padding:12px 14px; }
  .dash h3 { margin:0 0 10px; font-size:12px; font-weight:600; color:var(--muted);
             text-transform:uppercase; letter-spacing:.4px; }
  .dash .spark { width:100%; height:58px; display:block; }
  .dash .legend { display:flex; gap:14px; font-size:11px; color:var(--muted); margin-top:6px; }
  .dash .legend i { display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; }
  .dash .bar-row { display:grid; grid-template-columns: 1fr 34px; gap:8px; align-items:center;
                   font-size:12px; margin-bottom:6px; }
  .dash .bar-row .name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .dash .bar-row .num { text-align:right; color:var(--muted); }
  .dash .track { height:5px; border-radius:3px; background:#EDF1F7; margin-top:3px; overflow:hidden; }
  .dash .track span { display:block; height:100%; background:var(--accent); }
  .dash .classes { display:flex; height:9px; border-radius:5px; overflow:hidden; margin-bottom:8px; }
  .dash .classes span { display:block; height:100%; }
  .dash .cls-row { display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px; }
  body.dark .dash .box { background:#1B2432; border-color:#2A3546; }
  body.dark .dash .track { background:#26303F; }
</style>
</head>
<body>
<header>
  <h1>Обогащение событий SIEM — панель аналитика</h1>
  <div class="stats">
    <div class="live" id="live"><i></i><span id="live-text">поток</span></div>
    <div><b id="c-total">0</b>обработано всего</div>
    <div><b id="c-crit">0</b>критичных</div>
    <div><b id="c-block">0</b>решений о блокировке</div>
    <div><b id="c-fp">0</b>публичных объектов</div>
    <button class="theme" id="theme" title="светлая или тёмная тема">тема</button>
  </div>
</header>
<main>
  <section class="dash" id="dash">
    <div class="box">
      <h3>динамика событий</h3>
      <svg class="spark" id="spark" viewBox="0 0 320 58" preserveAspectRatio="none"></svg>
      <div class="legend"><span><i style="background:#1F5FC0"></i>всего</span>
        <span><i style="background:#B3261E"></i>блокировка</span></div>
    </div>
    <div class="box"><h3>топ правил</h3><div id="top-rules"></div></div>
    <div class="box"><h3>топ файлов</h3><div id="top-files"></div></div>
    <div class="box"><h3>классы</h3><div class="classes" id="cls-bar"></div><div id="cls-legend"></div></div>
  </section>
  <section class="card">
    <div class="filters">
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
      <button class="ghost" id="pause">пауза</button>
        <span class="counter" id="label-counter"></span>
      <button id="settings-open">настройки</button>
      <span class="counter" id="counter"></span>
    </div>
    <table>
      <thead>
      <tr><th data-sort="ts">Время</th><th data-sort="file">Файл</th>
          <th data-sort="action">Действие</th><th data-sort="sensitivity">Класс</th>
          <th data-sort="confidence">Уверенность</th><th data-sort="risk">Риск</th>
          <th data-sort="decision">Решение</th><th data-sort="rule">Правило</th></tr>
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
    <h2 class="sub" style="margin-top:18px;font-size:14px;">Правила политик</h2>
    <div class="hint">Выключенное правило не участвует в решениях. Изменения применяются сразу.</div>
    <div id="rules-fields"></div>
    <h2 class="sub" style="margin-top:18px;font-size:14px;">Последние изменения</h2>
    <div id="audit-list" class="audit"></div>
    <div class="actions">
      <button class="cancel" id="settings-cancel">отмена</button>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
        <button class="cancel" id="demo-start">▶ поток</button>
        <button class="cancel" id="demo-stop">■ стоп</button>
        <button class="cancel" id="demo-fill">+25 событий</button>
        <button class="cancel" id="demo-incident">инцидент</button>
        <span id="demo-status" style="font-size:12px;color:#5B6470"></span>
      </div>
      <button class="cancel" id="rules-reload">перечитать правила</button>
      <button class="save" id="settings-save">применить</button>
    </div>
    <div class="result" id="settings-result"></div>
  </div>
</div>
<script>
let DATA = [], SELECTED = null;
let SEEN = 0, MAX_ROWS = 200, MODAL_OPEN = false, RENDER_QUEUED = false;

function scheduleRender() {
  if (RENDER_QUEUED) return;
  RENDER_QUEUED = true;
  const run = () => { RENDER_QUEUED = false; render(); };
  if (window.requestAnimationFrame) requestAnimationFrame(run); else setTimeout(run, 120);
}
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
  const blob = new Blob([String.fromCharCode(0xFEFF) + lines.join(String.fromCharCode(10))], {type: 'text/csv;charset=utf-8'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'siem-events.csv';
  link.click();
  URL.revokeObjectURL(link.href);
}

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
function fmt(value) {
  return (value === null || value === undefined) ? '—' : value;
}
function bucketKey(value) {
  const text = (value || '').slice(11, 16);
  if (!text) return '';
  const [hours, minutes] = text.split(':').map(Number);
  if (Number.isNaN(hours) || Number.isNaN(minutes)) return '';
  const slot = Math.floor(minutes / 10) * 10;
  return `${String(hours).padStart(2, '0')}:${String(slot).padStart(2, '0')}`;
}

function sparkline(series, color, max) {
  if (!series.length) return '';
  if (series.length === 1) {
    const y = 50 - (series[0] / max) * 40;
    return `<circle cx="160" cy="${y.toFixed(1)}" r="3" fill="${color}"></circle>`;
  }
  const step = series.length > 1 ? 300 / (series.length - 1) : 0;
  const points = series.map((value, index) => {
    const x = 10 + index * step;
    const y = 50 - (value / max) * 40;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return `<polyline points="${points.join(' ')}" fill="none" stroke="${color}" stroke-width="1.8"
          stroke-linejoin="round" stroke-linecap="round"></polyline>`;
}

function topList(items, total, limit = 5) {
  return items.slice(0, limit).map(([name, count]) => `
    <div class="bar-row">
      <div><div class="name" title="${name}">${name}</div>
        <div class="track"><span style="width:${Math.round(count / total * 100)}%"></span></div></div>
      <div class="num">${count}</div>
    </div>`).join('') || '<div class="path">нет данных</div>';
}

function renderDashboard() {
  const spark = document.getElementById('spark');
  if (!spark) return;
  try {

  const moments = DATA
    .map(event => new Date(event.ts || 0))
    .filter(date => !Number.isNaN(date.getTime()));
  const slots = 18;
  const slotMs = 10 * 60 * 1000;
  const latest = moments.length ? Math.max(...moments.map(d => d.getTime())) : Date.now();
  const startSlot = Math.floor(latest / slotMs) - slots + 1;
  const totals = new Array(slots).fill(0);
  const blocks = new Array(slots).fill(0);
  for (const date of moments) {
    const index = Math.floor(date.getTime() / slotMs) - startSlot;
    if (index < 0 || index >= slots) continue;
    totals[index] += 1;
  }
  for (const event of DATA) {
    if (event.decision !== 'block') continue;
    const date = new Date(event.ts || 0);
    if (Number.isNaN(date.getTime())) continue;
    const index = Math.floor(date.getTime() / slotMs) - startSlot;
    if (index >= 0 && index < slots) blocks[index] += 1;
  }
  const max = Math.max(1, ...totals, ...blocks);
  spark.innerHTML = sparkline(totals, '#1F5FC0', max) + sparkline(blocks, '#B3261E', max);

  const ruleCounts = new Map();
  for (const event of DATA) {
    for (const rule of (event.rules || [])) ruleCounts.set(rule, (ruleCounts.get(rule) || 0) + 1);
  }
  const rules = Array.from(ruleCounts.entries()).sort((a, b) => b[1] - a[1]);
  const ruleTotal = Math.max(1, ...rules.map(item => item[1]));
  document.getElementById('top-rules').innerHTML = topList(rules, ruleTotal);

  const HIDDEN_LABEL = '(название скрыто)';
  const fileCounts = new Map();
  let hiddenCount = 0;
  for (const event of DATA) {
    const name = event.file || '—';
    if (event.hash_only || name === HIDDEN_LABEL) { hiddenCount += 1; continue; }
    fileCounts.set(name, (fileCounts.get(name) || 0) + 1);
  }
  const files = Array.from(fileCounts.entries()).sort((a, b) => b[1] - a[1]);
  const fileTotal = Math.max(1, ...files.map(item => item[1]));
  let filesHtml = topList(files, fileTotal);
  if (hiddenCount) {
    filesHtml += '<div class="bar-row"><div><div class="name">имя не раскрывается</div></div>' +
      '<div class="num">' + hiddenCount + '</div></div>';
  }
  document.getElementById('top-files').innerHTML = filesHtml;

  const colors = {secret: '#B3261E', confidential: '#C26A00', internal: '#1F5FC0', public: '#2E7D32'};
  const labels = {secret: 'secret', confidential: 'confidential', internal: 'internal', public: 'public'};
  const classCounts = {};
  for (const event of DATA) {
    const key = event.sensitivity || 'unknown';
    classCounts[key] = (classCounts[key] || 0) + 1;
  }
  const total = DATA.length || 1;
  document.getElementById('cls-bar').innerHTML = Object.entries(classCounts)
    .map(([key, count]) => `<span style="width:${count / total * 100}%;background:${colors[key] || '#8C99AC'}"></span>`)
    .join('');
  document.getElementById('cls-legend').innerHTML = Object.entries(classCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([key, count]) => `<div class="cls-row"><span>${labels[key] || key}</span>
      <span class="num" style="color:${colors[key] || '#8C99AC'}">${count}</span></div>`)
    .join('');
  } catch (error) {
    spark.parentElement.insertAdjacentHTML('beforeend',
      '<div class="path">ошибка дашборда: ' + error.message + '</div>');
  }
}

function fmtTime(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return (ts || '').slice(11, 19);
  return date.toLocaleTimeString('ru-RU', {hour12: false});
}

function render() {
  refreshActions();
  const rows = visibleRows();
  renderDashboard();
  const body = document.getElementById('rows');
  const shown = rows.slice(0, MAX_ROWS);
  document.getElementById('empty').style.display = rows.length ? 'none' : 'block';
  const STATS = window.__stats || {};
  document.getElementById('c-total').textContent =
    Math.max(SEEN || 0, STATS.seen || 0, DATA.length);
  document.getElementById('c-crit').textContent = DATA.filter(e => e.severity === 'critical').length;
  document.getElementById('c-block').textContent = DATA.filter(e => e.decision === 'block').length;
  document.getElementById('c-fp').textContent = DATA.filter(e => e.sensitivity === 'public').length;
  const counter = document.getElementById('counter');
  if (counter) counter.textContent = `показано ${shown.length} из ${DATA.length}`;
  document.querySelectorAll('th[data-sort]').forEach(th => {
    const arrow = th.dataset.sort === SORT.key ? (SORT.dir > 0 ? ' ▲' : ' ▼') : '';
    th.innerHTML = th.textContent.replace(/[ ▲▼]+$/, '') + arrow;
  });
  body.innerHTML = rows.map((e, index) => {
    const risk = Math.max(0, Math.min(1, e.risk || 0));
    const color = severityColor(e.severity);
    return `<tr data-id="${e.event_id}" class="${SELECTED === e.event_id ? 'sel' : ''}">
      <td class="num" title="${e.ts || ''}">${fmtTime(e.ts)}</td>
      <td><div class="file">${e.file || '—'}${e.hash_only ? ' <span class="hash" title="имя файла в событии отсутствует — файл известен только по отпечатку">имя скрыто</span>' : ''}</div><div class="path">${e.directory || ''}</div></td>
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
let SIEM_TEMPLATE = '';

function siemLink(event) {
  if (!SIEM_TEMPLATE) return '';
  const url = SIEM_TEMPLATE.replaceAll('{event_id}', encodeURIComponent(event.event_id || ''))
                            .replaceAll('{file}', encodeURIComponent(event.file || ''));
  return `<div class="row"><div class="k">в системе SIEM</div>
    <div class="v"><a href="${url}" target="_blank" rel="noopener">открыть событие в SIEM</a></div></div>`;
}

async function loadPanelMeta() {
  try {
    const response = await fetch('/ui/config', {cache: 'no-store'});
    if (!response.ok) return;
    const payload = await response.json();
    SIEM_TEMPLATE = payload.siem_url_template || '';
    if (SIEM_TEMPLATE && SELECTED) render();
  } catch (error) { }
}

let LABELS = new Map();

function labelBadge(event) {
  const label = LABELS.get(event.event_id);
  if (!label) return '';
  const text = label.label === 'confirmed' ? 'подтверждён' : 'ложное срабатывание';
  const color = label.label === 'confirmed' ? '#2E7D32' : '#B3261E';
  return `<span class="badge" style="background:#EEF1F6;color:${color}">${text}</span>`;
}

function labelBlock(event) {
  const label = LABELS.get(event.event_id);
  const comment = label && label.comment ? label.comment : '';
  return `<div class="row"><div class="k">оценка аналитика ${labelBadge(event)}</div>
    <div class="v">
      <input id="label-comment" placeholder="комментарий (необязательно)" value="${comment.replaceAll('"', '&quot;')}"
             style="width:100%;padding:5px 8px;border:1px solid #DCE3EE;border-radius:6px;font-size:12px">
      <select id="label-true-level" style="margin-top:6px;width:100%;padding:5px 8px;font-size:12px;
              border:1px solid #DCE3EE;border-radius:6px">
        <option value="">класс определён верно</option>
        <option value="public">на самом деле public</option>
        <option value="internal">на самом деле internal</option>
        <option value="confidential">на самом деле confidential</option>
        <option value="secret">на самом деле secret</option>
      </select>
      <div style="margin-top:6px;display:flex;gap:8px">
        <button class="chain-btn" onclick="labelEvent('${event.event_id}', 'confirmed')">подтвердить</button>
        <button class="chain-btn" onclick="labelEvent('${event.event_id}', 'false_positive')">ложное</button>
      </div>
      <div id="label-result" class="path" style="margin-top:4px"></div>
    </div></div>`;
}

async function loadLabels() {
  try {
    const response = await fetch('/ui/labels?limit=500', {cache: 'no-store'});
    const payload = await response.json();
    LABELS = new Map((payload.records || []).map(item => [String(item.event_id), item]));
    const counter = document.getElementById('label-counter');
    if (counter && payload.counts) {
      counter.textContent = `подтверждено ${payload.counts.confirmed}, ложных ${payload.counts.false_positive}`;
    }
    if (SELECTED) render();
  } catch (error) { /* оценки необязательны */ }
}

async function labelEvent(eventId, label) {
  const event = DATA.find(item => item.event_id === eventId) || {};
  const commentBox = document.getElementById('label-comment');
  const result = document.getElementById('label-result');
  try {
    const response = await fetch('/ui/label', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_id: eventId, label,
                            comment: commentBox ? commentBox.value : '',
                            file: event.file, path: event.path, directory: event.directory,
                            level: event.sensitivity,
                            true_level: (document.getElementById('label-true-level') || {}).value || '',
                            decision: event.decision, risk: event.risk})
    });
    const payload = await response.json();
    if (!response.ok) throw new Error((payload.errors || []).join('; '));
    if (result) result.textContent = 'сохранено: ' + (label === 'confirmed' ? 'инцидент подтверждён' : 'ложное срабатывание');
    await loadLabels();
    render();
  } catch (error) {
    if (result) result.textContent = 'не сохранено: ' + error.message;
  }
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
    ${siemLink(event)}
  ${labelBlock(event)}
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
      <button class="chain-btn" onclick="repeatEvent('${event.event_id}')"
              title="отправить это событие в сервис ещё раз">повторить</button>
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
  window.__stats = payload.stats || {};
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
let PAUSED = false, PENDING = 0;

function setLive(state) {
  const box = document.getElementById('live');
  const text = document.getElementById('live-text');
  if (!box || !text) return;
  box.classList.toggle('off', state === 'off');
  box.classList.toggle('paused', state === 'paused');
  text.textContent = state === 'live' ? 'поток' : state === 'paused' ? 'пауза' : 'нет связи';
}

function showPending() {
  const button = document.getElementById('pause');
  if (!button) return;
  button.textContent = PAUSED ? `продолжить${PENDING ? ' (' + PENDING + ')' : ''}` : 'пауза';
}

function connectStream() {
  if (!window.EventSource) { setLive('off'); return; }
  const source = new EventSource('/ui/stream');
  source.onopen = () => setLive(PAUSED ? 'paused' : 'live');
  source.onerror = () => setLive('off');
  source.onmessage = (message) => {
    let record;
    try { record = JSON.parse(message.data); } catch (error) { return; }
    if (PAUSED) { PENDING += 1; showPending(); return; }
    DATA = [record, ...DATA.filter(item => item.event_id !== record.event_id)].slice(0, 500);
    SEEN += 1;
    if (!SELECTED && record.decision === 'block') select(record.event_id);
    if (!MODAL_OPEN) scheduleRender();
  };
}

const pauseButton = document.getElementById('pause');
if (pauseButton) {
  pauseButton.addEventListener('click', () => {
    PAUSED = !PAUSED;
    if (!PAUSED) { PENDING = 0; refresh(); }
    setLive(PAUSED ? 'paused' : 'live');
    showPending();
  });
}

refresh();
if (!new URLSearchParams(location.search).has('static')) { connectStream(); } else { setLive('off'); }
loadPanelMeta();
loadLabels();
setInterval(() => { if (!window.EventSource) refresh(); }, 15000);

const SETTINGS_BOX = document.getElementById('settings');
const SETTINGS_FIELDS = document.getElementById('settings-fields');
const SETTINGS_RESULT = document.getElementById('settings-result');

async function openSettings() {
  MODAL_OPEN = true;
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
  const rulesBox = document.getElementById('rules-fields');
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
  const auditBox = document.getElementById('audit-list');
  if (auditBox) {
    auditBox.innerHTML = '';
    try {
      const response = await fetch('/ui/audit?limit=20', {cache: 'no-store'});
      const payload = await response.json();
      for (const item of (payload.records || [])) {
        const row = document.createElement('div');
        row.className = 'item';
        const name = item.rule ? ('правило ' + item.rule) : (item.key || 'изменение');
        const when = (item.audit_ts || '').slice(11, 19);
        row.innerHTML = '<div>' + name + ': ' + String(item.from) + ' → ' + String(item.to) +
                        ' <span>(' + (item.actor || '—') + ')</span></div>' +
                        '<span>' + when + '</span>';
        auditBox.appendChild(row);
      }
      if (!(payload.records || []).length) {
        auditBox.innerHTML = '<div class="item">изменений пока нет</div>';
      }
    } catch (error) { auditBox.innerHTML = '<div class="item">журнал недоступен</div>'; }
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
  const rules = {};
  for (const input of document.querySelectorAll('[data-rule]')) {
    rules[input.dataset.rule] = input.checked;
  }
  const response = await fetch('/ui/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({values, rules})
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
async function repeatEvent(eventId) {
  const event = DATA.find(item => item.event_id === eventId);
  if (!event) return;
  const payload = event.raw || {
    event_id: event.event_id, '@timestamp': event.ts, action: event.action,
    file: {path: event.path, name: event.file, directory: event.directory}
  };
  const result = document.getElementById('repeat-result');
  try {
    const response = await fetch('/v1/enrich', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const document_ = await response.json();
    if (result) {
      result.textContent = 'событие отправлено повторно: решение ' + (document_.policy_decision || '—') +
        ', риск ' + (document_.risk_score ?? 0).toFixed(2);
    }
    await loadEvents();
  } catch (error) {
    if (result) result.textContent = 'не удалось повторить: ' + error.message;
  }
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
}
document.getElementById('settings-cancel').addEventListener('click', () => {
  SETTINGS_BOX.classList.remove('open');
  MODAL_OPEN = false;
  scheduleRender();
});
document.getElementById('settings-save').addEventListener('click', saveSettings);

const demoStart = document.getElementById('demo-start');
const demoStop = document.getElementById('demo-stop');
const demoFill = document.getElementById('demo-fill');
const demoIncident = document.getElementById('demo-incident');
const demoStatus = document.getElementById('demo-status');

async function demoCall(path, body) {
  const response = await fetch(path, {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Analyst': 'panel'},
    body: JSON.stringify(body || {})});
  return response.json();
}

if (demoStart) {
  demoStart.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/start', {interval: 2, scenario: 'mixed'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'поток идёт' : (result.error || '');
  });
  demoStop.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/stop', {});
    if (demoStatus) demoStatus.textContent = 'остановлено, отправлено ' + (result.sent || 0);
  });
  demoIncident.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/events', {scenario: 'incident'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'инцидент добавлен' : (result.error || '');
  });
  demoFill.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/events', {count: 25, scenario: 'mixed'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'добавлено ' + result.sent : (result.error || '');
  });
}

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
}
</script>
</body>
</html>
"""

COMPACT_FIELDS = (
    "event_id", "ts", "action", "file", "path", "directory", "sensitivity",
    "sensitivity_ru", "confidence", "method", "reason", "risk", "severity",
    "decision", "rules", "depth", "external", "removable", "components",
)


HIDDEN_NAME = "(название скрыто)"


def _clean_name(name: str | None, path: str | None) -> str:
    """Имя файла для показа: хэши и служебные строки не выдаём за имя файла."""
    name = (name or "").strip()
    if not name or name.lower().startswith("sha256:"):
        path = (path or "").strip()
        if path and not path.lower().startswith("sha256:"):
            return path.replace("\\", "/").rsplit("/", 1)[-1]
        return HIDDEN_NAME
    return name


def _hash_only(file_info: dict[str, Any]) -> bool:
    """Имя файла неизвестно — объект известен только по отпечатку."""
    name = str(file_info.get("name") or "").strip().lower()
    path = str(file_info.get("path") or "").strip().lower()
    if name.startswith("sha256:") or (not name and path.startswith("sha256:")):
        return True
    hashes = file_info.get("hashes") or {}
    return bool(hashes) and not name and not path


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
        "hash_only": _hash_only(file_info) or _clean_name(
            file_info.get("name"), file_info.get("path")) == HIDDEN_NAME,
        "steps": _chain_steps(document),
        "endpoints": list(_chains_dict(document).get("external_endpoints") or [])[:6],
        "raw": document.get("raw_event") or None,
    }


class EventBuffer:
    """Кольцевой буфер последних обогащённых событий."""

    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)
        self._subscribers: list[Any] = []
        self._seen = 0
        self._replaced = 0

    def subscribe(self, callback: Any) -> None:
        """Подписать получателя на новые события (SSE-поток панели)."""
        self._subscribers.append(callback)

    def add(self, document: dict[str, Any]) -> None:
        record = compact(document)
        self._seen += 1
        if record.get("event_id"):
            kept = [i for i in self._items if i.get("event_id") != record["event_id"]]
            if len(kept) != len(self._items):
                self._replaced += 1
            self._items = deque(kept, maxlen=self._items.maxlen)
        self._items.append(record)
        for callback in list(self._subscribers):
            try:
                callback(record)
            except Exception:  # noqa: BLE001 - подписчик не должен ломать буфер
                self._subscribers.remove(callback)

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
            "seen": self._seen,
            "replaced": self._replaced,
            "capacity": self._items.maxlen,
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


RULES_HISTORY_DIR = "var/rules-history"
RULES_KEEP = 10


def snapshot_rules(config: Any) -> str | None:
    """Сохранить копию файла правил перед перезагрузкой."""
    from datetime import UTC, datetime

    path = Path(str(getattr(config.ml, "rules_file", "") or ""))
    if not path.exists():
        return None
    history = Path.cwd() / RULES_HISTORY_DIR
    history.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    target = history / f"rules-{stamp}.json"
    target.write_bytes(path.read_bytes())
    saved = sorted(history.glob("rules-*.json"))
    for old in saved[:-RULES_KEEP]:
        old.unlink(missing_ok=True)
    return target.name


def rules_versions() -> list[dict[str, Any]]:
    """Список сохранённых версий правил, новые первыми."""
    history = Path.cwd() / RULES_HISTORY_DIR
    if not history.exists():
        return []
    items = []
    for path in sorted(history.glob("rules-*.json"), reverse=True):
        items.append({"name": path.name, "size": path.stat().st_size})
    return items


def rollback_rules(config: Any, name: str) -> dict[str, Any]:
    """Вернуть файл правил из сохранённой версии."""
    history = Path.cwd() / RULES_HISTORY_DIR
    source = history / Path(name).name
    target = Path(str(getattr(config.ml, "rules_file", "") or ""))
    if not source.exists():
        return {"ok": False, "error": f"нет версии {name}"}
    if not target.parent.exists():
        return {"ok": False, "error": f"нет каталога {target.parent}"}
    target.write_bytes(source.read_bytes())
    return {"ok": True, "rules": str(target), "from": source.name}


DEMO_KEY = "demo_stream"


def _demo_state(app: Any) -> dict[str, Any]:
    state = getattr(app.state, DEMO_KEY, None)
    if state is None:
        state = {"running": False, "interval": 2.0, "scenario": "mixed",
                 "sent": 0, "task": None, "seq": 0}
        setattr(app.state, DEMO_KEY, state)
    return state


def _spread_events(events: list[dict[str, Any]], minutes: float = 0.0) -> list[dict[str, Any]]:
    """Разложить события по времени назад от текущего момента."""
    from datetime import UTC, datetime, timedelta

    if not events:
        return events
    moment = datetime.now(tz=UTC).replace(microsecond=0)
    if minutes <= 0:
        minutes = len(events)
    step = timedelta(minutes=minutes / max(1, len(events)))
    start = moment - step * len(events)
    for position, event in enumerate(events, 1):
        stamp = start + step * position
        event["@timestamp"] = stamp.isoformat().replace("+00:00", "Z")
    return events


def _unique_events(app: Any, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Уникальные идентификаторы и текущее время: генератор повторяет и то, и другое."""
    from datetime import UTC, datetime, timedelta

    state = _demo_state(app)
    state["seq"] = int(state.get("seq") or 0) + 1
    moment = datetime.now(tz=UTC).replace(microsecond=0)
    for position, event in enumerate(events, 1):
        event["id"] = f"{1700000000 + state['seq']}.{position:06d}"
        stamp = moment + timedelta(milliseconds=position * 100)
        event["@timestamp"] = stamp.isoformat().replace("+00:00", "Z")
    return events


def demo_fill(app: Any, count: int | None = 25, scenario: str = "mixed") -> dict[str, Any]:
    """Обогатить пачку сгенерированных событий и положить их в панель."""
    import sys

    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    if not tools_dir.exists():
        tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from generate_sample_events import build_events

    pipeline = _pipeline_of(app)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    buffer = getattr(app.state, "panel_buffer", None)
    if scenario in {'incident', 'attack'}:
        count = None  # у сценария фиксированная длина цепочки
    events = _unique_events(app, build_events(scenario=scenario,
                                             count=(max(1, min(count, 500)) if count else None)))
    _spread_events(events, minutes=20 if scenario in {'incident', 'attack'} else 90)
    sent = 0
    for event in events:
        _, _, document = pipeline.enrich_document("demo", event)
        if buffer is not None and not getattr(app.state, "panel_observed", False):
            buffer.add(document)
        sent += 1
    return {"ok": True, "sent": sent, "scenario": scenario}


async def demo_start(app: Any, interval: float = 2.0, scenario: str = "mixed") -> dict[str, Any]:
    """Запустить непрерывный поток событий в фоне."""
    import asyncio
    import sys

    state = _demo_state(app)
    if state["running"]:
        return {"ok": True, "running": True, "already": True, "sent": state["sent"]}

    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    if not tools_dir.exists():
        tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from generate_sample_events import stream_events

    pipeline = _pipeline_of(app)
    buffer = getattr(app.state, "panel_buffer", None)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}

    state.update({"running": True, "interval": interval, "scenario": scenario, "sent": 0})

    async def loop() -> None:
        from datetime import UTC, datetime

        started = datetime.now(tz=UTC).replace(microsecond=0)
        batch: list[dict[str, Any]] = []
        for event in stream_events(scenario=scenario, interval=0, repeat=0,
                                   start=started):
            batch.append(event)
            if len(batch) < 10:
                continue
            _unique_events(app, batch)
            for item in batch:
                if not state["running"]:
                    return
                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None and not getattr(app.state, "panel_observed", False):
                    buffer.add(document)
                state["sent"] += 1
                await asyncio.sleep(max(0.1, interval))
            batch = []
        if batch:
            _unique_events(app, batch)
            for item in batch:
                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None:
                    buffer.add(document)
                state["sent"] += 1
        return

    state["task"] = asyncio.create_task(loop())
    return {"ok": True, "running": True, "interval": interval, "scenario": scenario}


def demo_stop(app: Any) -> dict[str, Any]:
    state = _demo_state(app)
    state["running"] = False
    task = state.get("task")
    if task is not None:
        task.cancel()
    state["task"] = None
    return {"ok": True, "running": False, "sent": state["sent"]}


def demo_status(app: Any) -> dict[str, Any]:
    state = _demo_state(app)
    return {"running": bool(state["running"]), "interval": state["interval"],
            "scenario": state["scenario"], "sent": state["sent"]}


def _state_journal(config: Any) -> Any:
    from siem_enricher.ml.state import StateJournal

    return StateJournal(
        tenant=current_tenant(config),
        base=Path.cwd() / "ml" / "artifacts",
        rules_file=Path(str(getattr(config.ml, "rules_file", "") or "")),
        config_file=Path.cwd() / "config" / "config.local.json",
    )


def capture_state(app: Any, note: str = "") -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    entry = _state_journal(config).capture(
        actor=str(getattr(app.state, "audit_actor", "panel")), note=note
    )
    return {"ok": True, "state": entry}


def state_history(app: Any) -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"states": []}
    return {"states": _state_journal(config).entries()}


def rollback_state(app: Any, entry_id: str, restore_config: bool = False) -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    journal = _state_journal(config)
    try:
        result = journal.rollback(entry_id, restore_config=restore_config,
                                 actor=str(getattr(app.state, "audit_actor", "panel")))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    reloaded = reload_model(app)
    result["reload"] = reloaded
    _audit(app, {"kind": "state_rollback", "key": "ml/state", "from": "-", "to": entry_id})
    return {"ok": True, "result": result}


def reload_model(app: Any) -> dict[str, Any]:
    """Пересобрать классификатор с активной версией модели из реестра."""
    pipeline = _pipeline_of(app)
    config = getattr(app.state, "config", None)
    if pipeline is None or config is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    from siem_enricher.ml.classifier import build_classifier
    from siem_enricher.ml.registry import ModelRegistry

    fresh = build_classifier(config.ml, None, labels_path=config.labels_path)
    pipeline.classifier = fresh
    registry = ModelRegistry(current_tenant(config))
    active = registry.active() or {}
    _audit(app, {"kind": "model_reload", "key": "ml/artifact",
                 "from": "-", "to": active.get("id") or getattr(fresh, "model_version", "unknown")})
    return {
        "ok": True,
        "model_version": getattr(fresh, "model_version", "unknown"),
        "artifact": active.get("artifact"),
        "version": active.get("id"),
    }


def reload_rules(app: Any) -> dict[str, Any]:
    """Пересобрать классификатор по файлу правил без перезапуска сервиса."""
    pipeline = _pipeline_of(app)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    from siem_enricher.ml.classifier import build_classifier

    snapshot_rules(config)
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


def read_rules(app: Any) -> list[dict[str, Any]]:
    """Список правил политик с их состоянием."""
    engine = getattr(_pipeline_of(app), "policy_engine", None)
    rules = getattr(engine, "rules", None) or []
    return [{"id": rule.id, "title": rule.title or "", "enabled": bool(rule.enabled)}
            for rule in rules]


def _audit_logger(app: Any):
    """Логгер аудита, привязанный к пути из конфигурации."""
    from siem_enricher.audit import AuditLogger

    config = getattr(app.state, "config", None)
    path = getattr(config, "audit_log_path", None)
    if path is None:
        return None
    logger = getattr(app.state, "config_audit", None)
    if logger is None or logger.path != path:
        logger = AuditLogger(path)
        app.state.config_audit = logger
    return logger


def _audit(app: Any, record: dict[str, Any]) -> None:
    """Записать изменение конфигурации в журнал аудита."""
    logger = _audit_logger(app)
    if logger is None:
        return
    payload = dict(record)
    payload.setdefault("kind", "config_change")
    payload.setdefault("actor", getattr(app.state, "audit_actor", "panel"))
    try:
        from siem_enricher.metrics import service_metrics

        service_metrics().config_changes.inc(
            {"key": str(record.get("key") or record.get("rule") or "unknown")}
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        logger.write(payload)
        logger.flush()
    except Exception:  # noqa: BLE001 - аудит не должен ломать изменения
        pass


def read_audit_tail(app: Any, limit: int = 40) -> list[dict[str, Any]]:
    """Последние изменения конфигурации из журнала."""
    import json
    from pathlib import Path as _Path

    config = getattr(app.state, "config", None)
    path = getattr(config, "audit_log_path", None)
    if path is None or not _Path(path).exists():
        return []
    records: list[dict[str, Any]] = []
    for line in _Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if str(item.get("kind", "")).endswith("change"):
            records.append(item)
    return records[-limit:][::-1]


def current_tenant(config: Any) -> str:
    """Идентификатор организации из конфигурации (``default`` — общий режим)."""
    import re

    service = getattr(config, "service", None)
    raw = str(getattr(service, "tenant", "default") or "default").strip().lower()
    cleaned = re.sub(r"[^\w.-]+", "-", raw, flags=re.UNICODE).strip("-.")
    return cleaned or "default"


LABELS_FILE = "var/labels/analyst_labels.jsonl"
LABEL_LEVELS = ("public", "internal", "confidential", "secret")

LABEL_VALUES = {"confirmed": "инцидент подтверждён", "false_positive": "ложное срабатывание"}


def _labels_path(app: Any = None) -> Any:
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
    return path


def save_label(app: Any, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Сохранить оценку аналитика по событию."""
    import json
    from datetime import UTC, datetime

    event_id = str(payload.get("event_id") or "").strip()
    label = str(payload.get("label") or "").strip()
    errors: list[str] = []
    if not event_id:
        errors.append("не указан идентификатор события")
    if label not in LABEL_VALUES:
        errors.append("метка должна быть confirmed или false_positive")
    if errors:
        return None, errors

    predicted = str(payload.get("level") or "").strip() or None
    if predicted is not None and predicted not in LABEL_LEVELS:
        predicted = None
    true_level = str(payload.get("true_level") or "").strip() or None
    if true_level is not None and true_level not in LABEL_LEVELS:
        errors.append("верный класс должен быть одним из: public, internal, confidential, secret")
        return None, errors

    record = {
        "event_id": event_id,
        "label": label,
        "comment": str(payload.get("comment") or "").strip()[:500],
        "file": str(payload.get("file") or ""),
        "path": str(payload.get("path") or ""),
        "directory": str(payload.get("directory") or ""),
        "predicted_level": predicted,
        "true_level": true_level,
        "decision": str(payload.get("decision") or ""),
        "risk": payload.get("risk"),
        "actor": str(getattr(app.state, "audit_actor", "analyst")),
        "ts": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
    }
    try:
        from siem_enricher.metrics import service_metrics

        service_metrics().analyst_labels.inc({"label": label})
    except Exception:  # noqa: BLE001
        pass
    with _labels_path(app).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record, []


def export_training_rows(app: Any) -> list[dict[str, Any]]:
    """Собрать строки датасета из меток: путь -> верный класс.

    Целевой класс берётся из явной правки аналитика, а при подтверждении —
    из предсказания модели на момент разметки.
    """
    rows: dict[str, dict[str, Any]] = {}
    for record in reversed(read_labels(app, limit=100000)["records"]):
        path = str(record.get("path") or "").strip()
        if not path:
            continue
        target = record.get("true_level")
        if target is None and record.get("label") == "confirmed":
            target = record.get("predicted_level")
        if target not in LABEL_LEVELS:
            continue
        strength = "strong" if record.get("true_level") else "weak"
        rows[path.lower()] = {
            "path": path,
            "name": record.get("file") or path.rsplit("\\", 1)[-1],
            "level": target,
            "strength": strength,
            "event_id": record.get("event_id"),
            "label": record.get("label"),
            "actor": record.get("actor"),
            "ts": record.get("ts"),
        }
    return list(rows.values())


def read_labels(app: Any, limit: int = 200) -> dict[str, Any]:
    """Последние метки и сводка по ним."""
    import json

    path = _labels_path(app)
    records: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    latest: dict[str, dict[str, Any]] = {}
    for item in records:
        latest[str(item.get("event_id"))] = item
    counts = {"confirmed": 0, "false_positive": 0}
    for item in latest.values():
        key = str(item.get("label"))
        if key in counts:
            counts[key] += 1
    return {"records": records[-limit:][::-1], "latest": latest, "counts": counts}


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
        previous = bool(rule.enabled)
        rule.enabled = bool(enabled)
        applied.append(str(rule_id))
        if previous != rule.enabled:
            _audit(app, {"kind": "policy_rule_change", "rule": str(rule_id),
                         "from": previous, "to": rule.enabled})
    return applied, errors


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

    if applied:
        persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)}, app=app)
        for key in merged:
            if key in current and str(current[key]) != str(merged[key]):
                _audit(app, {"kind": "config_change", "key": key,
                             "from": current[key], "to": merged[key]})
    return applied, errors


SETTINGS_FILE = "var/runtime-settings.json"


def _settings_path(app: Any = None) -> Path:
    """Файл настроек организации: у каждой свой."""
    from pathlib import Path

    tenant = "default"
    config = getattr(getattr(app, "state", None), "config", None) if app is not None else None
    if config is not None:
        tenant = current_tenant(config)
    name = SETTINGS_FILE if tenant == "default" else f"var/runtime-settings-{tenant}.json"
    candidate = Path.cwd() / name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def persist_settings(values: dict[str, Any], rules: dict[str, Any] | None = None,
                     app: Any = None) -> None:
    """Сохранить действующие параметры и состояние правил, чтобы пережить перезапуск."""
    import json

    payload = {"values": values, "rules": rules or {}}
    try:
        _settings_path(app).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def restore_settings(app: Any = None) -> list[str]:
    """Один раз применить параметры, сохранённые в прошлый раз."""
    if getattr(app.state, "settings_restored", False):
        return []
    app.state.settings_restored = True
    import json

    path = _settings_path(app)
    if not path.exists():
        return []
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(saved, dict):
        return []
    values = saved.get("values") if isinstance(saved.get("values"), dict) else saved
    applied, _errors = apply_settings(app, values)
    if isinstance(saved.get("rules"), dict):
        rule_applied, _rule_errors = apply_rules(app, saved["rules"])
        applied.extend(rule_applied)
    return applied


def _panel_setting(app, name, default=None):
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


def register_panel(app, buffer) -> bool:
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

    @app.get("/ui/stream", include_in_schema=False)
    async def panel_stream(request: Request) -> Any:
        import asyncio
        import json

        from fastapi.responses import StreamingResponse

        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        buffer.subscribe(lambda record: queue.put_nowait(record))

        async def generator() -> Any:
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        record = await asyncio.wait_for(queue.get(), timeout=15)
                    except TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield "data: " + json.dumps(record, ensure_ascii=False) + "\n\n"
            finally:
                pass

        return StreamingResponse(generator(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.get("/ui/events", include_in_schema=False)
    async def panel_events(request: Request, limit: int = 200) -> Any:
        store: EventBuffer = request.app.state.panel_buffer
        return JSONResponse({"events": store.recent(limit), "stats": store.stats()})

    @app.post("/ui/label", include_in_schema=False)
    async def panel_label(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"errors": ["некорректный JSON"]}, status_code=400)
        record, errors = save_label(request.app, payload)
        if errors:
            return JSONResponse({"errors": errors}, status_code=400)
        return JSONResponse({"record": record, "counts": read_labels(request.app)["counts"]})

    @app.get("/ui/rules/versions", include_in_schema=False)
    async def panel_rules_versions(request: Request) -> Any:
        return JSONResponse({"versions": rules_versions()})

    @app.post("/ui/rules/rollback", include_in_schema=False)
    async def panel_rules_rollback(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        name = str((payload or {}).get("version") or "")
        result = rollback_rules(request.app.state.config, name)
        if not result.get("ok"):
            return JSONResponse(result, status_code=400)
        reloaded = reload_rules(request.app)
        result["reload"] = reloaded
        _audit(request.app, {"kind": "rules_rollback", "key": "config/rules.json",
                             "from": "-", "to": name})
        return JSONResponse(result)

    @app.get("/ui/demo", include_in_schema=False)
    async def panel_demo_status(request: Request) -> Any:
        return JSONResponse(demo_status(request.app))

    @app.post("/ui/demo/events", include_in_schema=False)
    async def panel_demo_events(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        count = int((payload or {}).get("count") or 25)
        scenario = str((payload or {}).get("scenario") or "mixed")
        return JSONResponse(demo_fill(request.app, count=count, scenario=scenario))

    @app.post("/ui/demo/start", include_in_schema=False)
    async def panel_demo_start(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        interval = float((payload or {}).get("interval") or 2.0)
        scenario = str((payload or {}).get("scenario") or "mixed")
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        return JSONResponse(await demo_start(request.app, interval=interval, scenario=scenario))

    @app.post("/ui/demo/stop", include_in_schema=False)
    async def panel_demo_stop(request: Request) -> Any:
        return JSONResponse(demo_stop(request.app))

    @app.get("/ui/state", include_in_schema=False)
    async def panel_state_list(request: Request) -> Any:
        return JSONResponse(state_history(request.app))

    @app.post("/ui/state/capture", include_in_schema=False)
    async def panel_state_capture(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        return JSONResponse(capture_state(request.app, str((payload or {}).get("note") or "")))

    @app.post("/ui/state/rollback", include_in_schema=False)
    async def panel_state_rollback(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        entry_id = str((payload or {}).get("state") or "")
        restore = bool((payload or {}).get("with_config"))
        result = rollback_state(request.app, entry_id, restore)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)

    @app.post("/ui/model/reload", include_in_schema=False)
    async def panel_model_reload(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        result = reload_model(request.app)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)

    @app.post("/ui/rules/reload", include_in_schema=False)
    async def panel_rules_reload(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        result = reload_rules(request.app)
        status = 200 if result.get("ok") else 400
        return JSONResponse(result, status_code=status)

    @app.get("/ui/labels/export", include_in_schema=False)
    async def panel_labels_export(request: Request, strength: str = "all") -> Any:
        from fastapi.responses import Response

        rows = export_training_rows(request.app)
        if strength in {"strong", "weak"}:
            rows = [row for row in rows if row.get("strength") == strength]
        body = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"
        return Response(content=body, media_type="application/jsonl",
                        headers={"Content-Disposition": "attachment; filename=labels_dataset.jsonl"})

    @app.get("/ui/labels", include_in_schema=False)
    async def panel_labels(request: Request, limit: int = 200) -> Any:
        data = read_labels(request.app, limit)
        return JSONResponse({"records": data["records"], "counts": data["counts"]})

    @app.get("/ui/audit", include_in_schema=False)
    async def panel_audit(request: Request, limit: int = 40) -> Any:
        return JSONResponse({"records": read_audit_tail(request.app, limit)})

    @app.get("/ui/config", include_in_schema=False)
    async def panel_config(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        restore_settings(request.app)
        return JSONResponse({"settings": SETTINGS_SCHEMA, "values": read_settings(request.app),
                             "rules": read_rules(request.app),
                             "siem_url_template": siem_link_template(request.app)})

    @app.post("/ui/config", include_in_schema=False)
    async def panel_config_save(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"applied": [], "errors": ["некорректный JSON"]}, status_code=400)
        restore_settings(request.app)
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        applied, errors = apply_settings(request.app, payload.get("values", {}))
        rule_changes = payload.get("rules") or {}
        if rule_changes:
            rule_applied, rule_errors = apply_rules(request.app, rule_changes)
            applied.extend(rule_applied)
            errors.extend(rule_errors)
        return JSONResponse({"applied": applied, "errors": errors,
                             "values": read_settings(request.app),
                             "rules": read_rules(request.app)})

    return True


__all__ = ["PANEL_HTML", "EventBuffer", "compact", "load_documents", "register_panel", "COMPACT_FIELDS"]

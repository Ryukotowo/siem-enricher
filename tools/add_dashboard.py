"""Мини-дашборд панели: динамика, топ правил и файлов, классы."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

CSS = """  .dash { display:grid; grid-template-columns: 1.4fr 1fr 1fr 1fr; gap:12px; padding:14px 24px 0; }
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
</style>"""

DASH = """  <section class="dash" id="dash">
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
"""

SECTION_ANCHOR = '  <section class="card">\n    <div class="filters">'

DASH_JS = '''function bucketKey(value) {
  const text = (value || '').slice(11, 16);
  if (!text) return '';
  const [hours, minutes] = text.split(':').map(Number);
  if (Number.isNaN(hours) || Number.isNaN(minutes)) return '';
  const slot = Math.floor(minutes / 10) * 10;
  return `${String(hours).padStart(2, '0')}:${String(slot).padStart(2, '0')}`;
}

function sparkline(series, color, max) {
  if (!series.length) return '';
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

  const buckets = new Map();
  const blocked = new Map();
  for (const event of DATA) {
    const key = bucketKey(event.ts);
    if (!key) continue;
    buckets.set(key, (buckets.get(key) || 0) + 1);
    if (event.decision === 'block') blocked.set(key, (blocked.get(key) || 0) + 1);
  }
  const keys = Array.from(buckets.keys()).sort();
  const totals = keys.map(key => buckets.get(key));
  const blocks = keys.map(key => blocked.get(key) || 0);
  const max = Math.max(1, ...totals, ...blocks);
  spark.innerHTML = sparkline(totals, '#1F5FC0', max) + sparkline(blocks, '#B3261E', max);

  const ruleCounts = new Map();
  for (const event of DATA) {
    for (const rule of (event.rules || [])) ruleCounts.set(rule, (ruleCounts.get(rule) || 0) + 1);
  }
  const rules = Array.from(ruleCounts.entries()).sort((a, b) => b[1] - a[1]);
  const ruleTotal = Math.max(1, ...rules.map(item => item[1]));
  document.getElementById('top-rules').innerHTML = topList(rules, ruleTotal);

  const fileCounts = new Map();
  for (const event of DATA) {
    const name = event.file || '—';
    fileCounts.set(name, (fileCounts.get(name) || 0) + 1);
  }
  const files = Array.from(fileCounts.entries()).sort((a, b) => b[1] - a[1]);
  const fileTotal = Math.max(1, ...files.map(item => item[1]));
  document.getElementById('top-files').innerHTML = topList(files, fileTotal);

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
}

'''

RENDER_ANCHOR = "  const rows = visibleRows();"

CALL_ANCHOR = "  if (counter) counter.textContent = `показано ${rows.length} из ${DATA.length}`;"


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "renderDashboard" in text:
        print("дашборд уже есть")
        return 0
    checks = [
        ("</style>", CSS),
        (SECTION_ANCHOR, DASH + SECTION_ANCHOR),
        (RENDER_ANCHOR, RENDER_ANCHOR + "\n  renderDashboard();"),
        (CALL_ANCHOR, CALL_ANCHOR),
        ("function render() {", DASH_JS + "function render() {"),
    ]
    for old, new in checks:
        if old not in text:
            print(f"!! не найдено: {old[:46]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:44]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

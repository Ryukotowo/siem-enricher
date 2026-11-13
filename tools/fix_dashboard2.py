"""Дашборд: непрерывная шкала времени и отдельный учёт скрытых имён."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

SPARK_OLD = '''function sparkline(series, color, max) {
  if (!series.length) return '';
  const step = series.length > 1 ? 300 / (series.length - 1) : 0;'''
SPARK_NEW = '''function sparkline(series, color, max) {
  if (!series.length) return '';
  if (series.length === 1) {
    const y = 50 - (series[0] / max) * 40;
    return `<circle cx="160" cy="${y.toFixed(1)}" r="3" fill="${color}"></circle>`;
  }
  const step = series.length > 1 ? 300 / (series.length - 1) : 0;'''

SERIES_OLD = '''  const buckets = new Map();
  const blocked = new Map();
  for (const event of DATA) {
    const key = bucketKey(event.ts);
    if (!key) continue;
    buckets.set(key, (buckets.get(key) || 0) + 1);
    if (event.decision === 'block') blocked.set(key, (blocked.get(key) || 0) + 1);
  }
  const keys = Array.from(buckets.keys()).sort();
  const totals = keys.map(key => buckets.get(key));
  const blocks = keys.map(key => blocked.get(key) || 0);'''
SERIES_NEW = '''  const moments = DATA
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
  }'''

FILES_OLD = '''  const fileCounts = new Map();
  for (const event of DATA) {
    const name = event.file || '—';
    fileCounts.set(name, (fileCounts.get(name) || 0) + 1);
  }
  const files = Array.from(fileCounts.entries()).sort((a, b) => b[1] - a[1]);
  const fileTotal = Math.max(1, ...files.map(item => item[1]));
  document.getElementById('top-files').innerHTML = topList(files, fileTotal);'''
FILES_NEW = '''  const HIDDEN_LABEL = '(название скрыто)';
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
  document.getElementById('top-files').innerHTML = filesHtml;'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new, label in (
        (SPARK_OLD, SPARK_NEW, "точка вместо пустой линии"),
        (SERIES_OLD, SERIES_NEW, "непрерывная шкала по 10 минут"),
        (FILES_OLD, FILES_NEW, "скрытые имена отдельной строкой"),
    ):
        if new in text:
            continue
        if old not in text:
            print(f"  предупреждение: не найдено — {label}")
            continue
        text = text.replace(old, new, 1)
        changed += 1
        print(f"  {label}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

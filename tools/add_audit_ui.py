"""Показ журнала изменений настроек в панели + тест аудита."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

HTML_OLD = '    <div id="rules-fields"></div>'
HTML_NEW = ('    <div id="rules-fields"></div>\n'
            '    <h2 class="sub" style="margin-top:18px;font-size:14px;">Последние изменения</h2>\n'
            '    <div id="audit-list" class="audit"></div>')

CSS_OLD = "  #settings .result { font-size:12px; color:var(--muted); margin-top:10px; }"
CSS_NEW = (CSS_OLD + "\n"
           "  .audit { font-size:12px; color:#2B3442; max-height:150px; overflow:auto; }\n"
           "  .audit .item { padding:5px 0; border-bottom:1px solid #EEF1F6; display:flex;\n"
           "                 justify-content:space-between; gap:10px; }\n"
           "  .audit .item span { color:var(--muted); white-space:nowrap; }\n"
           "  body.dark .audit { color:#DCE3EE; }")

JS_OLD = "  SETTINGS_BOX.classList.add('open');"
JS_NEW = '''  const auditBox = document.getElementById('audit-list');
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
  SETTINGS_BOX.classList.add('open');'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "audit-list" in text:
        print("журнал в панели уже есть")
        return 0
    for old, new in ((CSS_OLD, CSS_NEW), (HTML_OLD, HTML_NEW), (JS_OLD, JS_NEW)):
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:44]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("панель: журнал изменений добавлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

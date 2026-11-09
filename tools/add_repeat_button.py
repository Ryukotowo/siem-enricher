"""Кнопка «повторить событие»: повторная отправка исходного документа."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

COMPACT_OLD = '''        "steps": _chain_steps(document),
        "endpoints": list(_chains_dict(document).get("external_endpoints") or [])[:6],
    }'''
COMPACT_NEW = '''        "steps": _chain_steps(document),
        "endpoints": list(_chains_dict(document).get("external_endpoints") or [])[:6],
        "raw": document.get("raw_event") or None,
    }'''

BUTTON_OLD = '''<button class="chain-btn" onclick="toggleChain(this)">'''
BUTTON_NEW = '''<button class="chain-btn" onclick="repeatEvent('${event.event_id}')"
              title="отправить это событие в сервис ещё раз">повторить</button>
    <button class="chain-btn" onclick="toggleChain(this)">'''

JS_ANCHOR = "const exportBtn = document.getElementById('export');"
JS_ADD = '''async function repeatEvent(eventId) {
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

const exportBtn = document.getElementById('export');'''

RESULT_ANCHOR = '''<button class="chain-btn" onclick="toggleChain(this)">'''
# маркер вывода результата добавляем после блока происхождения
RESULT_HOOK = '''<div class="row"><div class="k">происхождение</div>'''
RESULT_NEW = '''<div class="row"><div class="k">происхождение</div>'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "repeatEvent" in text:
        print("кнопка уже есть")
        return 0
    for old, new, label in (
        (COMPACT_OLD, COMPACT_NEW, "raw в срезе документа"),
        (BUTTON_OLD, BUTTON_NEW, "кнопка в карточке"),
        (JS_ANCHOR, JS_ADD, "обработчик повтора"),
    ):
        if old not in text:
            print(f"!! не найдено: {label}")
            return 1
        text = text.replace(old, new)
        print(f"патч: {label}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

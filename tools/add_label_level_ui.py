"""Интерфейс разметки: верный класс и передача пути."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

BLOCK_OLD = '''      <input id="label-comment" placeholder="комментарий (необязательно)" value="${comment.replaceAll('"', '&quot;')}"
             style="width:100%;padding:5px 8px;border:1px solid #DCE3EE;border-radius:6px;font-size:12px">
      <div style="margin-top:6px;display:flex;gap:8px">'''

BLOCK_NEW = '''      <input id="label-comment" placeholder="комментарий (необязательно)" value="${comment.replaceAll('"', '&quot;')}"
             style="width:100%;padding:5px 8px;border:1px solid #DCE3EE;border-radius:6px;font-size:12px">
      <select id="label-true-level" style="margin-top:6px;width:100%;padding:5px 8px;font-size:12px;
              border:1px solid #DCE3EE;border-radius:6px">
        <option value="">класс определён верно</option>
        <option value="public">на самом деле public</option>
        <option value="internal">на самом деле internal</option>
        <option value="confidential">на самом деле confidential</option>
        <option value="secret">на самом деле secret</option>
      </select>
      <div style="margin-top:6px;display:flex;gap:8px">'''

SEND_OLD = '''      body: JSON.stringify({event_id: eventId, label, comment: commentBox ? commentBox.value : '',
                            file: event.file, decision: event.decision, risk: event.risk})'''

SEND_NEW = '''      body: JSON.stringify({event_id: eventId, label,
                            comment: commentBox ? commentBox.value : '',
                            file: event.file, path: event.path, directory: event.directory,
                            level: event.sensitivity,
                            true_level: (document.getElementById('label-true-level') || {}).value || '',
                            decision: event.decision, risk: event.risk})'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "label-true-level" in text:
        print("уже есть")
        return 0
    for old, new in ((BLOCK_OLD, BLOCK_NEW), (SEND_OLD, SEND_NEW)):
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("панель: выбор верного класса и передача пути")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

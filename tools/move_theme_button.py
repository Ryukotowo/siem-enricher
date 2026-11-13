"""Кнопка смены темы в шапке панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HEADER_OLD = '''    <div><b id="c-fp">0</b>публичных объектов</div>
  </div>
</header>'''
HEADER_NEW = '''    <div><b id="c-fp">0</b>публичных объектов</div>
    <button class="theme" id="theme" title="светлая или тёмная тема">тема</button>
  </div>
</header>'''

CSS_ANCHOR = "  header .stats b {"
CSS_ADD = '''  header .theme { align-self:center; margin-left:8px; padding:6px 10px; font-size:12px;
    background:rgba(255,255,255,.12); color:#fff; border:1px solid rgba(255,255,255,.28);
    border-radius:6px; cursor:pointer; }
  header .theme:hover { background:rgba(255,255,255,.2); }

'''

REMOVE_OLD = '    <button class="ghost" id="theme">тема</button>\n'


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if 'header .theme' not in text:
        if CSS_ANCHOR not in text:
            print("!! не найден CSS шапки")
            return 1
        text = text.replace(CSS_ANCHOR, CSS_ADD + CSS_ANCHOR, 1)
        changed += 1
        print("  стиль кнопки темы для шапки")
    if 'class="theme"' not in text:
        if HEADER_OLD not in text:
            print("!! не найдена разметка шапки")
            return 1
        text = text.replace(HEADER_OLD, HEADER_NEW, 1)
        changed += 1
        print("  кнопка темы перенесена в шапку")
    if REMOVE_OLD in text:
        text = text.replace(REMOVE_OLD, "", 1)
        changed += 1
        print("  старая кнопка из панели действий убрана")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

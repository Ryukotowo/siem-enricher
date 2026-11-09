"""Исправление идемпотентности и применение патча ответа /ui/config."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
TOOL = ROOT / "tools" / "add_template_response.py"

OLD = '"rules": read_rules(request.app)})'
NEW = ('"rules": read_rules(request.app),\n'
       '                             "siem_url_template": siem_link_template(request.app)})')


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if NEW in text:
        print("уже применено")
    elif OLD in text:
        text = text.replace(OLD, NEW, 1)
        PANEL.write_text(text, encoding="utf-8")
        ast.parse(text)
        print("ответ /ui/config обновлён")
    else:
        print("!! не найдено")
        return 1

    tool = TOOL.read_text(encoding="utf-8")
    tool = tool.replace('if "siem_url_template" in text:', 'if NEW in text:', 1)
    TOOL.write_text(tool, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

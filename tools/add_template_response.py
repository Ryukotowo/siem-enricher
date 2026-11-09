"""Добавление шаблона ссылки в ответ /ui/config."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '"rules": read_rules(request.app)})'
NEW = ('"rules": read_rules(request.app),\n'
       '                             "siem_url_template": siem_link_template(request.app)})')


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if NEW in text:
        print("шаблон уже в ответе")
        return 0
    if OLD not in text:
        print("!! не найдено")
        return 1
    text = text.replace(OLD, NEW, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("шаблон добавлен в ответ /ui/config")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

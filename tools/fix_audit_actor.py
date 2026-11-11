"""Автор изменения из заголовка X-Analyst для POST /ui/config."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '        applied, errors = apply_settings(request.app, payload.get("values", {}))'
NEW = ('        request.app.state.audit_actor = (request.headers.get("X-Analyst")\n'
       '                                        or getattr(request.client, "host", "panel"))\n'
       '        applied, errors = apply_settings(request.app, payload.get("values", {}))')


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if 'X-Analyst' in text and text.count("X-Analyst") >= 4:
        print("уже есть")
        return 0
    if OLD not in text:
        print("!! не найден обработчик сохранения")
        return 1
    text = text.replace(OLD, NEW, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("автор изменения читается и при сохранении")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

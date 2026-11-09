"""Вызов loadPanelMeta при загрузке панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

ANCHOR = "if (!new URLSearchParams(location.search).has('static')) { connectStream(); } else { setLive('off'); }"


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "loadPanelMeta();" in text:
        print("вызов уже есть")
        return 0
    if ANCHOR not in text:
        print("!! не найдена строка запуска потока")
        return 1
    text = text.replace(ANCHOR, ANCHOR + "\nloadPanelMeta();", 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("loadPanelMeta добавлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

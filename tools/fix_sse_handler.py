"""Аккуратно обновить обработчик SSE по номерам строк."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"


def main() -> int:
    lines = PANEL.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if "source.onmessage" in line)
    end = start
    while "};" not in lines[end]:
        end += 1
    body = [
        "  source.onmessage = (message) => {",
        "    let record;",
        "    try { record = JSON.parse(message.data); } catch (error) { return; }",
        "    if (PAUSED) { PENDING += 1; showPending(); return; }",
        "    DATA = [record, ...DATA.filter(item => item.event_id !== record.event_id)].slice(0, 500);",
        "    SEEN += 1;",
        "    if (!SELECTED && record.decision === 'block') select(record.event_id);",
        "    if (!MODAL_OPEN) scheduleRender();",
        "  };",
    ]
    lines[start:end + 1] = body
    text = "\n".join(lines) + "\n"
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("обработчик SSE переписан: счётчик и отложенный рендер")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

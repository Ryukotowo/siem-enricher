"""Убрать недостижимый цикл из demo_start и лишние импорты."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '''        return

        for event in ():  # недостижимый цикл: оставлен для читаемости диффа
            if not state["running"]:
                break
            _, _, document = pipeline.enrich_document("demo", event)
            if buffer is not None:
                buffer.add(document)
            state["sent"] += 1
            await asyncio.sleep(max(0.1, interval))
'''

NEW = "        return\n"


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if OLD not in text:
        print("нечего чистить")
        return 0
    PANEL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("недостижимый цикл удалён")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

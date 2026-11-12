"""Пункт 3: сильные и слабые метки в экспорте датасета."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

ROWS_OLD = '''        rows[path.lower()] = {
            "path": path,
            "name": record.get("file") or path.rsplit("\\\\", 1)[-1],
            "level": target,
            "event_id": record.get("event_id"),
            "label": record.get("label"),
            "actor": record.get("actor"),
            "ts": record.get("ts"),
        }'''
ROWS_NEW = '''        strength = "strong" if record.get("true_level") else "weak"
        rows[path.lower()] = {
            "path": path,
            "name": record.get("file") or path.rsplit("\\\\", 1)[-1],
            "level": target,
            "strength": strength,
            "event_id": record.get("event_id"),
            "label": record.get("label"),
            "actor": record.get("actor"),
            "ts": record.get("ts"),
        }'''

ROUTE_OLD = '''    async def panel_labels_export(request: Request) -> Any:
        from fastapi.responses import Response

        rows = export_training_rows(request.app)'''
ROUTE_NEW = '''    async def panel_labels_export(request: Request, strength: str = "all") -> Any:
        from fastapi.responses import Response

        rows = export_training_rows(request.app)
        if strength in {"strong", "weak"}:
            rows = [row for row in rows if row.get("strength") == strength]'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if '"strength": strength' in text:
        print("уже есть")
        return 0
    for old, new in ((ROWS_OLD, ROWS_NEW), (ROUTE_OLD, ROUTE_NEW)):
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("экспорт: добавлена сила метки и фильтр strength")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

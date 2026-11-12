"""Метки, пригодные для обучения: путь, предсказанный и верный класс."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

LEVELS = 'LABEL_LEVELS = ("public", "internal", "confidential", "secret")\n\n'

RECORD_OLD = '''    record = {
        "event_id": event_id,
        "label": label,
        "comment": str(payload.get("comment") or "").strip()[:500],
        "file": str(payload.get("file") or ""),
        "decision": str(payload.get("decision") or ""),
        "risk": payload.get("risk"),'''

RECORD_NEW = '''    predicted = str(payload.get("level") or "").strip() or None
    if predicted is not None and predicted not in LABEL_LEVELS:
        predicted = None
    true_level = str(payload.get("true_level") or "").strip() or None
    if true_level is not None and true_level not in LABEL_LEVELS:
        errors.append("верный класс должен быть одним из: public, internal, confidential, secret")
        return None, errors

    record = {
        "event_id": event_id,
        "label": label,
        "comment": str(payload.get("comment") or "").strip()[:500],
        "file": str(payload.get("file") or ""),
        "path": str(payload.get("path") or ""),
        "directory": str(payload.get("directory") or ""),
        "predicted_level": predicted,
        "true_level": true_level,
        "decision": str(payload.get("decision") or ""),
        "risk": payload.get("risk"),'''

HELPER_ANCHOR = "def read_labels(app: Any, limit: int = 200) -> dict[str, Any]:"
HELPER = '''def export_training_rows(app: Any) -> list[dict[str, Any]]:
    """Собрать строки датасета из меток: путь -> верный класс.

    Целевой класс берётся из явной правки аналитика, а при подтверждении —
    из предсказания модели на момент разметки.
    """
    rows: dict[str, dict[str, Any]] = {}
    for record in reversed(read_labels(app, limit=100000)["records"]):
        path = str(record.get("path") or "").strip()
        if not path:
            continue
        target = record.get("true_level")
        if target is None and record.get("label") == "confirmed":
            target = record.get("predicted_level")
        if target not in LABEL_LEVELS:
            continue
        rows[path.lower()] = {
            "path": path,
            "name": record.get("file") or path.rsplit("\\\\", 1)[-1],
            "level": target,
            "event_id": record.get("event_id"),
            "label": record.get("label"),
            "actor": record.get("actor"),
            "ts": record.get("ts"),
        }
    return list(rows.values())


def read_labels(app: Any, limit: int = 200) -> dict[str, Any]:'''

ROUTE_ANCHOR = '    @app.get("/ui/labels", include_in_schema=False)'
ROUTE = '''    @app.get("/ui/labels/export", include_in_schema=False)
    async def panel_labels_export(request: Request) -> Any:
        from fastapi.responses import Response

        rows = export_training_rows(request.app)
        body = "\\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\\n"
        return Response(content=body, media_type="application/jsonl",
                        headers={"Content-Disposition": "attachment; filename=labels_dataset.jsonl"})

'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "export_training_rows" in text:
        print("уже есть")
        return 0
    if RECORD_OLD not in text:
        print("!! не найден блок record в save_label")
        return 1
    text = text.replace(RECORD_OLD, RECORD_NEW, 1)
    text = text.replace("LABEL_VALUES = {", LEVELS + "LABEL_VALUES = {", 1)
    text = text.replace(HELPER_ANCHOR, HELPER, 1)
    text = text.replace(ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR, 1)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("панель: путь, верный класс и экспорт датасета")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Валидация пакета событий: массив, объекты, не более 500."""

from __future__ import annotations

import ast
from pathlib import Path

ROUTES = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "routes.py"


def main() -> int:
    lines = ROUTES.read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.strip() == "if not isinstance(events, list):")
    block = [
        "    if not isinstance(events, list):",
        '        return JSONResponse(',
        '            {"detail": "ожидается массив событий или объект {events: [...]}"},',
        "            status_code=422,",
        "        )",
        "    if len(events) > 500:",
        "        return JSONResponse(",
        '            {"detail": "за один запрос принимается не более 500 событий"},',
        "            status_code=422,",
        "        )",
        "    if any(not isinstance(item, dict) for item in events):",
        '        return JSONResponse({"detail": "каждое событие должно быть объектом"},',
        "                           status_code=422)",
    ]
    end = index
    while "return" not in lines[end]:
        end += 1
    lines[index:end + 1] = block
    text = "\n".join(lines) + "\n"
    if "from fastapi.responses import JSONResponse" not in text:
        position = text.index("from fastapi import")
        end_import = text.index("\n", position) + 1
        text = text[:end_import] + "from fastapi.responses import JSONResponse\n" + text[end_import:]
    ROUTES.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("валидация пакета добавлена")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

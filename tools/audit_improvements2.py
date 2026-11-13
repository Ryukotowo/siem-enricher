"""Ограничение размера тела запроса и валидация пакета событий."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"
ROUTES = ROOT / "src" / "siem_enricher" / "service" / "routes.py"

LIMIT_CODE = '''

def _install_body_limit(app: Any, limit: int = 2_000_000) -> None:
    """Отклонять слишком большие тела запросов: защита от случайных и злонамеренных объёмов."""
    from fastapi.responses import JSONResponse

    @app.middleware("http")
    async def body_limit(request: Any, call_next: Any) -> Any:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                {"detail": f"тело запроса больше {limit} байт"}, status_code=413
            )
        return await call_next(request)

'''

INSTALL_OLD = "    _install_api_key_guard(app, config)"
INSTALL_NEW = "    _install_body_limit(app)\n    _install_api_key_guard(app, config)"

VALIDATE_OLD = '''    if not isinstance(events, list):
        return {"error": "ожидается {events: [...]} или список событий", "results": []}'''
VALIDATE_NEW = '''    if not isinstance(events, list):
        return JSONResponse(
            {"detail": "ожидается массив событий или объект {events: [...]}"}, status_code=422
        )
    if len(events) > 500:
        return JSONResponse(
            {"detail": "за один запрос принимается не более 500 событий"}, status_code=422
        )
    if any(not isinstance(item, dict) for item in events):
        return JSONResponse({"detail": "каждое событие должно быть объектом"}, status_code=422)'''

IMPORT_OLD = "from siem_enricher.version import VERSION"
IMPORT_NEW = "from siem_enricher.version import VERSION"


def patch_app() -> int:
    text = APP.read_text(encoding="utf-8")
    if "_install_body_limit" in text:
        print("app: лимит уже есть")
        return 0
    anchor = "def _install_api_key_guard("
    text = text.replace(anchor, LIMIT_CODE.strip("\n") + "\n\n" + anchor, 1)
    text = text.replace(INSTALL_OLD, INSTALL_NEW, 1)
    APP.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("app: ограничение тела запроса 2 МБ")
    return 1


def patch_routes() -> int:
    text = ROUTES.read_text(encoding="utf-8")
    if "не более 500 событий" in text:
        print("routes: валидация уже есть")
        return 0
    if VALIDATE_OLD not in text:
        print("!! не найден блок валидации пакета")
        return 0
    text = text.replace(VALIDATE_OLD, VALIDATE_NEW, 1)
    if "from fastapi.responses import JSONResponse" not in text:
        marker = "from fastapi import"
        index = text.index(marker)
        end = text.index("\n", index) + 1
        text = text[:end] + "from fastapi.responses import JSONResponse\n" + text[end:]
    ROUTES.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("routes: валидация пакета и лимит 500 событий")
    return 1


def main() -> int:
    patch_app()
    patch_routes()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

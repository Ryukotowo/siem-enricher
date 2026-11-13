"""Два ключа: читающий и пишущий, с передачей через заголовок или cookie."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"

FIELD_OLD = '    api_key: str = ""'
FIELD_NEW = '    api_key: str = ""\n    read_key: str = ""'

DEFAULTS_OLD = '        "api_key": "",'
DEFAULTS_NEW = '        "api_key": "",\n        "read_key": "",'

OLD_BLOCK_START = 'def _install_api_key_guard(app: Any, config: AppConfig) -> None:'
OLD_BLOCK_END = 'def _noop() -> None:'

NEW_BLOCK = '''def _install_api_key_guard(app: Any, config: AppConfig) -> None:
    """Разграничить доступ: пишущий ключ меняет состояние, читающий только смотрит.

    Ключ принимается заголовком X-API-Key или cookie siem_key (её ставит страница
    панели при переходе по ссылке с параметром ?key=). Проверки состояния и метрики
    остаются открытыми для мониторинга.
    """
    write_key = str(getattr(config.http, "api_key", "") or "")
    read_key = str(getattr(config.http, "read_key", "") or "")
    if not write_key and not read_key:
        logger.warning("HTTP-ключи не заданы: доступ открыт")
        return

    import hmac

    from fastapi.responses import JSONResponse

    public_paths = {"/healthz", "/readyz", "/metrics", "/ui", "/favicon.ico"}
    write_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def given(request: Any) -> str:
        return (request.headers.get("X-API-Key")
                or request.cookies.get("siem_key")
                or request.query_params.get("key")
                or "")

    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        path = request.url.path
        if path in public_paths:
            response = await call_next(request)
            supplied = request.query_params.get("key")
            if path == "/ui" and supplied:
                response.set_cookie("siem_key", supplied, httponly=True, samesite="strict")
            return response

        token = given(request)
        if request.method.upper() in write_methods:
            ok = bool(write_key) and hmac.compare_digest(token, write_key)
            detail = "требуется пишущий ключ (X-API-Key)"
        else:
            allowed = [key for key in (read_key, write_key) if key]
            ok = any(hmac.compare_digest(token, key) for key in allowed) if allowed else True
            detail = "требуется читающий ключ (X-API-Key)"
        if not ok:
            return JSONResponse({"detail": detail}, status_code=401)
        return await call_next(request)


'''


def patch_config() -> int:
    text = CONFIG.read_text(encoding="utf-8")
    if "read_key" in text:
        print("config: read_key уже есть")
        return 0
    if FIELD_OLD not in text:
        print("!! не найдено поле api_key")
        return 0
    text = text.replace(FIELD_OLD, FIELD_NEW, 1)
    if DEFAULTS_OLD in text:
        text = text.replace(DEFAULTS_OLD, DEFAULTS_NEW, 1)
    CONFIG.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("config: http.read_key")
    return 1


def patch_app() -> int:
    text = APP.read_text(encoding="utf-8")
    start = text.find(OLD_BLOCK_START)
    if start < 0:
        print("!! не найден guard")
        return 0
    end = text.find("def _noop()", start)
    if end < 0:
        print("!! не найден конец guard")
        return 0
    text = text[:start] + NEW_BLOCK + text[end:]
    APP.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("app: разграничение читающего и пишущего ключа")
    return 1


def main() -> int:
    patch_config()
    patch_app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

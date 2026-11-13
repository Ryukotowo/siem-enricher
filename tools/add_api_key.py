"""API-ключ для изменяющих запросов."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"

FIELD_OLD = '    metrics_port: int = 9101'
FIELD_NEW = '    metrics_port: int = 9101\n    api_key: str = ""'

MIDDLEWARE = '''
    _install_api_key_guard(app, config)
'''

ANCHOR = '    app.include_router(routes.router)'

GUARD = '''def _install_api_key_guard(app: Any, config: AppConfig) -> None:
    """Требовать X-API-Key для изменяющих запросов, если ключ задан.

    Чтение панели, метрики и проверки состояния остаются открытыми, чтобы
    мониторинг и просмотр не зависели от ключа.
    """
    expected = str(getattr(config.http, "api_key", "") or "")
    if not expected:
        logger.warning("HTTP API-ключ не задан: изменяющие запросы открыты")
        return

    import hmac

    from fastapi.responses import JSONResponse

    open_paths = {"/healthz", "/readyz", "/ui", "/ui/stream", "/metrics"}
    open_prefixes = ("/ui/events", "/ui/audit", "/ui/labels", "/ui/state", "/ui/rules/versions")

    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        method = request.method.upper()
        path = request.url.path
        protected = method in {"POST", "PUT", "PATCH", "DELETE"}
        if protected and path not in open_paths and not path.startswith(open_prefixes):
            provided = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(provided, expected):
                return JSONResponse({"detail": "требуется заголовок X-API-Key"}, status_code=401)
        return await call_next(request)

'''

INSTALL = '''    app.state.started_at = time.time()
'''


def main() -> int:
    changed = 0

    text = CONFIG.read_text(encoding="utf-8")
    if "api_key" not in text:
        if FIELD_OLD not in text:
            print("!! не найдено поле metrics_port")
            return 1
        text = text.replace(FIELD_OLD, FIELD_NEW, 1)
        defaults_old = '        "metrics_port": 9101,'
        if defaults_old in text:
            text = text.replace(defaults_old, '        "metrics_port": 9101,\n        "api_key": "",', 1)
        CONFIG.write_text(text, encoding="utf-8")
        ast.parse(text)
        changed += 1
        print("config: http.api_key")

    app_text = APP.read_text(encoding="utf-8")
    if "_install_api_key_guard" not in app_text:
        app_text = app_text.replace('logger = get_logger("service.app")',
                                    'logger = get_logger("service.app")\n\n\n' + GUARD + 'def _noop() -> None:\n    """Заглушка, чтобы сохранить структуру модуля."""\n', 1)
        if ANCHOR not in app_text:
            print("!! не найден include_router")
            return 1
        app_text = app_text.replace(ANCHOR, MIDDLEWARE.strip("\n") + "\n" + ANCHOR, 1)
        APP.write_text(app_text, encoding="utf-8")
        ast.parse(app_text)
        changed += 1
        print("app: middleware проверки ключа")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

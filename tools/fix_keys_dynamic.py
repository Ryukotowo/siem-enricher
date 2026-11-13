"""Ключи читаются на каждом запросе: конфигурация может меняться без перезапуска."""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "app.py"

OLD_HEAD = '''    write_key = str(getattr(config.http, "api_key", "") or "")
    read_key = str(getattr(config.http, "read_key", "") or "")
    if not write_key and not read_key:
        logger.warning("HTTP-ключи не заданы: доступ открыт")
        return

    import hmac
'''
NEW_HEAD = '''    if not (getattr(config.http, "api_key", "") or getattr(config.http, "read_key", "")):
        logger.warning("HTTP-ключи не заданы: доступ открыт")

    import hmac
'''

OLD_MID = '''    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        path = request.url.path'''
NEW_MID = '''    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        settings = getattr(request.app.state, "config", config).http
        write_key = str(getattr(settings, "api_key", "") or "")
        read_key = str(getattr(settings, "read_key", "") or "")
        path = request.url.path
        if not write_key and not read_key:
            return await call_next(request)'''


def main() -> int:
    text = APP.read_text(encoding="utf-8")
    changed = 0
    if OLD_HEAD in text:
        text = text.replace(OLD_HEAD, NEW_HEAD, 1)
        changed += 1
    if OLD_MID in text:
        text = text.replace(OLD_MID, NEW_MID, 1)
        changed += 1
    APP.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

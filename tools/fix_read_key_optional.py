"""Чтение защищается только если задан читающий ключ."""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "app.py"

OLD = '''        else:
            allowed = [key for key in (read_key, write_key) if key]
            ok = any(hmac.compare_digest(token, key) for key in allowed) if allowed else True
            detail = "требуется читающий ключ (X-API-Key)"'''

NEW = '''        else:
            if not read_key:
                ok = True  # читающий ключ не задан — чтение открыто
            else:
                allowed = [key for key in (read_key, write_key) if key]
                ok = any(hmac.compare_digest(token, key) for key in allowed)
            detail = "требуется читающий ключ (X-API-Key)"'''


def main() -> int:
    text = APP.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найден блок читающего ключа")
        return 1
    APP.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("чтение защищается только при заданном read_key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

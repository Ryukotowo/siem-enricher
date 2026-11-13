"""Пропускать тест лимита тела без fastapi."""

from __future__ import annotations

import ast
from pathlib import Path

TEST = Path(__file__).resolve().parents[1] / "tests" / "integration" / "test_http_hardening.py"

OLD = "class BodyLimitTest(unittest.TestCase):"
NEW = ('@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")\n'
       "class BodyLimitTest(unittest.TestCase):")


def main() -> int:
    text = TEST.read_text(encoding="utf-8")
    if NEW in text:
        print("уже добавлено")
        return 0
    if OLD not in text:
        print("!! не найден класс")
        return 1
    TEST.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("декоратор добавлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

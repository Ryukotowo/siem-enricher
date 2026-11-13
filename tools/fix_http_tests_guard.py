"""Пропуск HTTP-тестов без fastapi и установка extras в CI."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "tests" / "integration" / "test_panel_http.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"

HAS_GUARD = '''import importlib.util

HAS_HTTP = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)

if HAS_HTTP:
    from fastapi.testclient import TestClient
else:  # pragma: no cover - без extras сервис недоступен
    TestClient = None  # type: ignore[assignment]
'''


def patch_test() -> int:
    text = TEST.read_text(encoding="utf-8")
    if "HAS_HTTP" in text:
        print("тесты: пропуск уже есть")
        return 0
    text = text.replace("from fastapi.testclient import TestClient\n", HAS_GUARD, 1)
    text = text.replace("class PanelHttpTest(unittest.TestCase):",
                        '@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")\nclass PanelHttpTest(unittest.TestCase):', 1)
    text = text.replace("class ApiKeyTest(unittest.TestCase):",
                        '@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")\nclass ApiKeyTest(unittest.TestCase):', 1)
    TEST.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("тесты: skipUnless и безопасный импорт")
    return 0


def patch_ci() -> int:
    text = CI.read_text(encoding="utf-8")
    if 'pip install -e ".[service]"' in text:
        print("CI: extras уже установлены")
        return 0
    old = "          pip install -e .\n"
    new = '          pip install -e ".[service]"\n'
    if old not in text:
        print("!! не найден шаг установки")
        return 0
    CI.write_text(text.replace(old, new, 1), encoding="utf-8")
    print("CI: установка сервисных extras")
    return 0


def main() -> int:
    patch_test()
    patch_ci()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

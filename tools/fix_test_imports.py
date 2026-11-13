"""Порядок импортов в HTTP-тестах: без E402 и с сортировкой."""

from __future__ import annotations

import ast
from pathlib import Path

TEST = Path(__file__).resolve().parents[1] / "tests" / "integration" / "test_panel_http.py"

HEAD_OLD = '''from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import importlib.util

HAS_HTTP = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)

if HAS_HTTP:
    from fastapi.testclient import TestClient
else:  # pragma: no cover - без extras сервис недоступен
    TestClient = None  # type: ignore[assignment]

from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.metrics import reset_metrics, service_metrics
from siem_enricher.service.app import create_app
from tests import PROJECT_ROOT
'''

HEAD_NEW = '''from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.metrics import reset_metrics, service_metrics
from siem_enricher.service.app import create_app
from tests import PROJECT_ROOT

HAS_HTTP = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)

if HAS_HTTP:
    from fastapi.testclient import TestClient  # noqa: E402
else:  # pragma: no cover - без extras сервис недоступен
    TestClient = None  # type: ignore[assignment]
'''


def main() -> int:
    text = TEST.read_text(encoding="utf-8")
    if HEAD_NEW in text:
        print("импорты уже в порядке")
        return 0
    if HEAD_OLD not in text:
        print("!! не найден блок импортов")
        return 1
    text = text.replace(HEAD_OLD, HEAD_NEW, 1)
    TEST.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("импорты упорядочены")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

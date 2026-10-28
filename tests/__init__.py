"""Тесты сервиса обогащения.

Набор написан на стандартном ``unittest`` (не требует pytest) и при этом совместим
с pytest: ``pytest`` собирает классы ``unittest.TestCase`` без дополнительных плагинов.

Запуск без внешних зависимостей::

    python -m unittest discover -s tests -t . -v

Запуск через pytest (если установлен)::

    pytest
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _candidate in (ROOT / "src", ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

#: Корень проекта — используется тестами для доступа к конфигурации и фикстурам
PROJECT_ROOT = ROOT

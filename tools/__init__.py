"""Инструменты сопровождения проекта: генерация событий, заглушка SIEM, проверки."""

from __future__ import annotations

import sys
from pathlib import Path

# Пакет ``src`` добавляется в путь, чтобы инструменты работали без установки проекта.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

__all__ = ["add_src_to_path"]


def add_src_to_path() -> None:
    """Добавить каталог ``src`` в ``sys.path`` (идемпотентно)."""
    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))

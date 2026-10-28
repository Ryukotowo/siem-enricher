"""Запуск сервиса как модуля: ``python -m siem_enricher ...``."""

from __future__ import annotations

import sys

from siem_enricher.cli import main

if __name__ == "__main__":
    sys.exit(main())

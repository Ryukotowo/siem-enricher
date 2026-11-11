"""Значок CI и раздел о качестве в README."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

BADGES = (
    "![ci](https://github.com/Ryukotowo/siem-enricher/actions/workflows/ci.yml/badge.svg)"
    "(https://github.com/Ryukotowo/siem-enricher/actions/workflows/ci.yml)\n"
    "![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)\n"
    "![tests](https://img.shields.io/badge/tests-140-brightgreen)\n"
)

QUALITY = """
## Качество кода

- `ruff check src tests` — без замечаний; правила в `pyproject.toml`
- `python -m unittest discover -s tests -t .` — 140 тестов
- CI на GitHub Actions: линтер, тесты на Python 3.11 и 3.12, проверка конфигурации
  при каждом push и pull request

```bash
pip install -e .
ruff check src tests
python -m unittest discover -s tests -t .
```
"""


def main() -> int:
    text = README.read_text(encoding="utf-8")
    changed = 0
    if "badge.svg" not in text:
        lines = text.splitlines()
        lines.insert(2, BADGES.rstrip())
        text = "\n".join(lines) + "\n"
        changed += 1
        print("значок CI добавлен")
    if "## Качество кода" not in text:
        marker = "\n## Состав (7 модулей)"
        if marker in text:
            text = text.replace(marker, QUALITY + marker, 1)
        else:
            text = text.rstrip() + "\n" + QUALITY
        changed += 1
        print("раздел о качестве добавлен")
    README.write_text(text, encoding="utf-8")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

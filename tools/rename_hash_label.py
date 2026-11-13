"""Понятный заголовок вместо «файл по хэшу»."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
TEST = ROOT / "tests" / "unit" / "test_panel.py"

PAIRS = [
    ('        return "(файл по хэшу)"', '        return "(название скрыто)"'),
    ('title="имя пришло хэшем, полного имени в событии нет">хэш</span>',
     'title="имя файла в событии отсутствует — файл известен только по отпечатку">имя скрыто</span>'),
]

TEST_PAIRS = [
    ('self.assertEqual(record["file"], "(файл по хэшу)")',
     'self.assertEqual(record["file"], "(название скрыто)")'),
]


def patch(path: Path, pairs: list[tuple[str, str]], label: str) -> int:
    text = path.read_text(encoding="utf-8")
    changed = 0
    for old, new in pairs:
        if new in text:
            continue
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
    if changed:
        path.write_text(text, encoding="utf-8")
        ast.parse(text)
    print(f"  {label}: изменений {changed}")
    return changed


def main() -> int:
    patch(PANEL, PAIRS, "panel.py")
    patch(TEST, TEST_PAIRS, "test_panel.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

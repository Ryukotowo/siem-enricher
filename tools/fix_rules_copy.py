"""Копирование правил без метаданных: Windows-монтирование не даёт utime."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

PAIRS = [
    ("    shutil.copy2(path, target)", "    target.write_bytes(path.read_bytes())"),
    ("    shutil.copy2(source, target)", "    target.write_bytes(source.read_bytes())"),
]


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
    if changed:
        text = text.replace("    import shutil\n\n", "", 2)
        PANEL.write_text(text, encoding="utf-8")
        ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

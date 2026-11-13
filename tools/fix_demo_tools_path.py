"""Путь к tools/ вычисляется от модуля панели, а не от текущего каталога."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '''    tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))'''

NEW = '''    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    if not tools_dir.exists():
        tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    count = text.count(OLD)
    if not count:
        print("!! не найден блок поиска tools")
        return 1
    text = text.replace(OLD, NEW)
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"исправлено вхождений: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Правка сетки дашборда и диагностика ошибок рендера."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

GRID_OLD = "  .dash { display:grid; grid-template-columns: 1.4fr 1fr 1fr 1fr; gap:12px; padding:14px 24px 0; }"
GRID_NEW = "  .dash { display:grid; grid-template-columns: 1.4fr 1fr 1fr 1fr; gap:12px; grid-column:1 / -1; }"

START_OLD = "function renderDashboard() {\n  const spark = document.getElementById('spark');"
START_NEW = "function renderDashboard() {\n  const spark = document.getElementById('spark');\n  if (!spark) return;\n  try {"

END_OLD = "    .join('');\n}\n\nfunction render() {"
END_NEW = (
    "    .join('');\n"
    "  } catch (error) {\n"
    "    spark.parentElement.insertAdjacentHTML('beforeend',\n"
    "      '<div class=\"path\">ошибка дашборда: ' + error.message + '</div>');\n"
    "  }\n"
    "}\n\nfunction render() {"
)


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if GRID_OLD in text:
        text = text.replace(GRID_OLD, GRID_NEW, 1)
        changed += 1
        print("сетка: дашборд на всю ширину")
    if START_OLD in text:
        text = text.replace(START_OLD, START_NEW, 1)
        changed += 1
        print("добавлен try")
    if END_OLD in text:
        text = text.replace(END_OLD, END_NEW, 1)
        changed += 1
        print("добавлен catch с сообщением")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}, синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

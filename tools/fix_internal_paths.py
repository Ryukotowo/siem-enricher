"""Заменить пути internal-примеров на те, что классификатор относит к internal."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

PAIRS = [
    (r'r"C:\Projects\Отчет_о_работе_2025.docx"', r'r"C:\Документы\Отчет_о_работе_2025.docx"'),
    (r'r"C:\Projects\Техническое_задание_на_разработку.docx"',
     r'r"C:\Инструкции\Инструкция_по_делопроизводству.docx"'),
    (r'r"C:\Общие\Регламент_информационной_безопасности.pdf"',
     r'r"C:\Регламенты\Регламент_информационной_безопасности.pdf"'),
    (r'r"C:\Temp\черновик_письма.txt"', r'r"C:\Документы\Служебная_записка_черновик.docx"'),
    (r'r"\\srv-file-01\обмен\Общий_отчет_за_квартал.xlsx"',
     r'r"\\srv-file-01\документы\Отчет_за_квартал.docx"'),
]


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if new in text:
            continue
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print(f"  {old[:50]} -> {new[:50]}")
        else:
            print(f"  не найдено: {old[:60]}")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

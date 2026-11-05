"""Снимки записи событий в Quickwit и отчёт с ними."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from docx import Document  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: E402
from docx.shared import Cm, Pt  # noqa: E402

import render_screens  # noqa: E402

VKR = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\vkr")
SCREENS = ROOT / "var" / "screens"
PROJECT = render_screens.PROJECT

FIGURES = [
    ("qw_1_create.png", "qw_create.txt",
     'wsl curl -s -XPOST localhost:7280/api/v1/indexes -d @index.json',
     "Рисунок 1 – Создание индекса обогащённых событий в Quickwit"),
    ("qw_2_ingest.png", "qw_ingest.txt",
     'wsl curl -s -XPOST "localhost:7280/api/v1/siem-enriched/ingest?commit=force" -d @events.ndjson',
     "Рисунок 2 – Запись 136 обогащённых событий в индекс"),
    ("qw_3_search.png", "qw_search.txt",
     'wsl curl -s -XPOST localhost:7280/api/v1/siem-enriched/search -d @block.json',
     "Рисунок 3 – Поиск по решениям: события с блокировкой"),
    ("qw_4_agg.png", "qw_agg.txt",
     'wsl curl -s -XPOST localhost:7280/api/v1/siem-enriched/search -d @aggs.json',
     "Рисунок 4 – Распределение событий по решению, классу и уровню риска"),
]


def build_images() -> list[tuple[Path, str]]:
    result: list[tuple[Path, str]] = []
    for filename, source, command, caption in FIGURES:
        rows: list[tuple[str, str]] = [("prompt", PROJECT + " " + command)]
        rows.extend(("output", line) for line in render_screens.read_lines(source))
        rows.append(("prompt", PROJECT))
        path = render_screens.draw_window(rows, filename)
        result.append((path, caption))
        print(f"{filename}")
    return result


def build_report(images: list[tuple[Path, str]]) -> Path:
    document = Document()
    section = document.sections[0]
    section.left_margin = Cm(2.0)
    section.right_margin = Cm(1.5)
    section.top_margin = Cm(1.8)
    section.bottom_margin = Cm(1.8)

    style = document.styles["Normal"]
    style.font.name = "Times New Roman"
    style.font.size = Pt(14)
    style.paragraph_format.line_spacing = 1.4
    style.paragraph_format.first_line_indent = Cm(1.25)
    style.paragraph_format.space_after = Pt(0)

    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.first_line_indent = Cm(0)
    run = title.add_run("Запись обогащённых событий в Quickwit")
    run.bold = True

    intro = document.add_paragraph()
    intro.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    intro.add_run(
        "Сервис отдаёт обогащённые события в приёмник; ниже показан полный путь записи: "
        "создание индекса со схемой, загрузка 136 событий реального прогона, поиск по решению "
        "политики и агрегаты по классу конфиденциальности и уровню риска. Движок — Quickwit "
        "0.8.1, документы содержат поля класса, истории и риска, посчитанные сервисом."
    )

    for path, caption in images:
        picture = document.add_paragraph()
        picture.paragraph_format.first_line_indent = Cm(0)
        picture.alignment = WD_ALIGN_PARAGRAPH.CENTER
        picture.paragraph_format.space_before = Pt(8)
        picture.paragraph_format.space_after = Pt(4)
        picture.paragraph_format.keep_with_next = True
        picture.add_run().add_picture(str(path), width=Cm(17.0))

        caption_paragraph = document.add_paragraph()
        caption_paragraph.paragraph_format.first_line_indent = Cm(0)
        caption_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        caption_paragraph.paragraph_format.space_after = Pt(10)
        caption_run = caption_paragraph.add_run(caption)
        caption_run.font.size = Pt(12)

    target = VKR / "Снимки_Quickwit.docx"
    document.save(target)
    return target


def main() -> int:
    images = build_images()
    report = build_report(images)
    print(f"отчёт: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

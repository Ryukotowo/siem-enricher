"""Подобрать пути, которые классификатор относит к internal."""

import sys
from pathlib import Path

sys.path.insert(0, "src")

from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.logging_setup import setup_logging

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [
    r"C:\Регламенты\Регламент_информационной_безопасности.pdf",
    r"C:\Инструкции\Инструкция_по_делопроизводству.docx",
    r"C:\Документы\Положение_об_отделе.docx",
    r"C:\Отдел\Отчет_о_работе_2025.docx",
    r"C:\Прочее\черновик_письма.txt",
    r"C:\Документы\Служебная_записка.docx",
    r"C:\Общие\Регламент_информационной_безопасности.pdf",
    r"C:\Notes\черновик_письма.txt",
]

setup_logging(level="ERROR", fmt="json")
config = load_config(ROOT / "config" / "config.local.json")
pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
for path in CANDIDATES:
    assessment = pipeline.classifier.predict(path)
    print(f"{assessment.level.value:<13} {assessment.method:<9} {path}")
pipeline.close()

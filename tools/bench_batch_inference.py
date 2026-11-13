"""Микробенчмарк: батчевый инференс на разных и повторяющихся именах."""

import sys
import time

sys.path.insert(0, "src")

from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.logging_setup import setup_logging

setup_logging(level="ERROR", fmt="json")
config = load_config("config/config.local.json")


def run(paths: list[str], batch: bool) -> float:
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    events = [
        pipeline.normalize("test", {
            "event_id": f"e{index}", "ts": "2026-11-13T10:00:00Z", "action": "read",
            "user": "ivanov", "host": "ws", "path": path,
        })
        for index, path in enumerate(paths)
    ]
    started = time.perf_counter()
    if batch:
        pipeline.enrich_batch(events)
    else:
        for event in events:
            pipeline.enrich(event)
    elapsed = time.perf_counter() - started
    pipeline.close()
    return elapsed / len(events) * 1000


distinct = [rf"C:\Отдел{i:02d}\Документ_проекта_{i:03d}.docx" for i in range(64)]
same = [r"C:\HR\Зарплатная_ведомость_2025.xlsx"] * 64

for label, paths in (("разные имена", distinct), ("одно имя", same)):
    one = run(paths, batch=False)
    many = run(paths, batch=True)
    print(f"{label}: по одному {one:.2f} мс/соб, пачкой {many:.2f} мс/соб, "
          f"ускорение x{one / many:.2f}")

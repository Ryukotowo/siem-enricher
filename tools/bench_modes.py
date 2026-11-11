"""Единый замер трёх режимов для документов."""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402


def measure(events: list[dict], *, ml: str, database: bool, summaries: bool) -> tuple[float, int]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.type = ml
    config.provenance.sqlite_path = str(Path(tempfile.mkdtemp()) / "bench.db")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=not database)
    pipeline.builder.use_summaries = summaries
    started = time.perf_counter()
    count = 0
    for raw in events:
        pipeline.enrich_document("gensec", raw)
        count += 1
    elapsed = time.perf_counter() - started
    pipeline.close()
    return elapsed / count * 1000, count / elapsed


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    events = [json.loads(line) for line in
              (ROOT / "var" / "load" / "events_1k.jsonl").read_text(encoding="utf-8-sig").splitlines()
              if line.strip()]

    modes = [
        ("правила, без истории", dict(ml="heuristic", database=False, summaries=True)),
        ("гибрид, без истории", dict(ml="transformer", database=False, summaries=True)),
        ("гибрид, поток, обход", dict(ml="transformer", database=True, summaries=False)),
        ("гибрид, поток, сводки", dict(ml="transformer", database=True, summaries=True)),
    ]
    for label, options in modes:
        ms, speed = measure(events, **options)
        print(f"  {label:<24} {ms:6.2f} мс   {speed:7.1f} соб/с")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

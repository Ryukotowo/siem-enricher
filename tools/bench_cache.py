"""Замер эффекта кэша классификации: один и тот же набор дважды в одном процессе."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402


def run(events: list[dict], cache_size: int) -> tuple[float, dict]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.cache_size = cache_size
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    started = time.perf_counter()
    for raw in events:
        pipeline.enrich_document("bench", raw)
    duration = time.perf_counter() - started
    info = pipeline.classifier.describe().get("cache", {})
    pipeline.close()
    return duration, info


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    raw_events = [json.loads(line) for line in
                  (ROOT / "var" / "experiment" / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
                  if line.strip()]
    doubled = raw_events + raw_events

    print(f"событий: {len(doubled)} (набор дважды)")
    for cache_size in (0, 4096):
        duration, info = run(doubled, cache_size)
        label = "без кэша" if cache_size == 0 else "с кэшем"
        print(f"  {label:<9} {duration:6.2f} с   {len(doubled) / duration:5.2f} соб/с   {info}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

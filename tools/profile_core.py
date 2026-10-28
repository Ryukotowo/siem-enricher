"""Профилирование ядра: где на самом деле уходит время при обогащении события."""

from __future__ import annotations

import cProfile
import io
import json
import pstats
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402

EVENTS = ROOT / "var" / "demo" / "stand.jsonl"
LIMIT = 40


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    if not EVENTS.exists():
        print(f"!! нет файла событий: {EVENTS}")
        return 1
    config = load_config(ROOT / "config/config.local.json")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)

    raw_events = [json.loads(line) for line in EVENTS.read_text(encoding="utf-8").splitlines() if line.strip()]
    raw_events = raw_events[:LIMIT]
    normalized = [pipeline.normalize("profile", raw) for raw in raw_events]

    profiler = cProfile.Profile()
    profiler.enable()
    for event in normalized:
        pipeline.enrich(event)
    profiler.disable()

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.sort_stats("cumulative").print_stats(18)
    output = stream.getvalue()

    total = 0.0
    for line in output.splitlines():
        if "function calls" in line and "in" in line:
            try:
                total = float(line.split(" in ")[1].split(" seconds")[0])
            except (IndexError, ValueError):
                total = 0.0
    print(f"событий: {len(normalized)}; суммарно: {total:.2f} с; "
          f"на событие: {total / max(len(normalized), 1) * 1000:.1f} мс\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

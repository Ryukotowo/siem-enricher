"""Замер полного конвейера: обход против материализованных сводок."""

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


def run(events: list[dict], use_summaries: bool) -> tuple[float, int]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.provenance.sqlite_path = str(Path(tempfile.mkdtemp()) / "measure.db")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=False)
    pipeline.builder.use_summaries = use_summaries
    started = time.perf_counter()
    count = 0
    for raw in events:
        pipeline.enrich_document("gensec", raw)
        count += 1
    elapsed = time.perf_counter() - started
    pipeline.close()
    return elapsed, count


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    events = [json.loads(line) for line in
              (ROOT / "var" / "load" / "events_1k.jsonl").read_text(encoding="utf-8-sig").splitlines()
              if line.strip()]

    results: dict[str, float] = {}
    for use_summaries in (False, True):
        elapsed, count = run(events, use_summaries)
        label = "сводки" if use_summaries else "обход "
        results[label] = count / elapsed
        print(f"  {label}: {elapsed:6.2f} с -> {count / elapsed:6.1f} соб/с")

    base = results["обход "]
    gain = results["сводки"] / base
    print(f"ускорение: ×{gain:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Инвариант: сводка и обход дают одинаковые цепочки, плюс замер скорости."""

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


def compare(events: list[dict], in_memory: bool) -> tuple[int, int]:
    """Сравнить цепочки из сводок и из обхода на одном потоке событий."""
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.type = "heuristic"
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=in_memory)
    builder = pipeline.builder
    paths: list[str] = []
    for raw in events:
        event = pipeline.normalize("gensec", raw)
        pipeline.enrich(event)
        paths.extend(str(item.path) for item in event.files)

    checked = mismatched = 0
    for path in dict.fromkeys(paths):
        builder.use_summaries = True
        fast = builder.chain_for(path)
        builder.use_summaries = False
        builder._chain_cache.clear()
        slow = builder.chain_for(path)
        builder.use_summaries = True
        checked += 1
        if (len(fast.steps), tuple(fast.external_endpoints)) != (len(slow.steps), tuple(slow.external_endpoints)):
            mismatched += 1
            if mismatched <= 3:
                print(f"  расхождение: {path}")
                print(f"    сводка: шагов {len(fast.steps)}, внешние {fast.external_endpoints}")
                print(f"    обход:  шагов {len(slow.steps)}, внешние {slow.external_endpoints}")
    pipeline.close()
    return checked, mismatched


def speed(events: list[dict], use_summaries: bool) -> tuple[float, int]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.type = "heuristic"
    config.provenance.sqlite_path = str(Path(tempfile.mkdtemp()) / "check.db")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=False)
    pipeline.builder.use_summaries = use_summaries
    count = 0
    started = time.perf_counter()
    for raw in events:
        pipeline.enrich_document("gensec", raw)
        count += 1
    elapsed = time.perf_counter() - started
    pipeline.close()
    return elapsed, count


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    events = [json.loads(line) for line in
              (ROOT / "var" / "load" / "events_1k.jsonl").read_text(encoding="utf-8-sig").splitlines()[:400]
              if line.strip()]

    print("=== инвариант «сводка == обход» ===")
    checked, mismatched = compare(events, in_memory=True)
    print(f"проверено путей: {checked}, расхождений: {mismatched}")

    print("\n=== скорость (400 событий, sqlite) ===")
    for use_summaries in (False, True):
        elapsed, count = speed(events, use_summaries)
        label = "сводки" if use_summaries else "обход "
        print(f"  {label}: {elapsed:5.2f} с -> {count / elapsed:6.1f} соб/с")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

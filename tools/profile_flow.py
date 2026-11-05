"""Профиль обработки событий: где реально уходит время."""

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
from siem_enricher.enricher import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    events = [json.loads(line) for line in
              (ROOT / "var" / "load" / "events_1k.jsonl").read_text(encoding="utf-8-sig").splitlines()[:40]
              if line.strip()]
    config = load_config(ROOT / "config" / "config.local.json")

    profiler = cProfile.Profile()
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=False)
    profiler.enable()
    for raw in events:
        pipeline.enrich_document("gensec", raw)
    profiler.disable()
    pipeline.close()

    stats = pstats.Stats(profiler)
    rows = sorted(stats.stats.items(), key=lambda item: item[1][3], reverse=True)[:16]
    for (path, line, name), (_cc, _nc, _tt, cum, _callers) in rows:
        short = path.split("siem_enricher")[-1] if "siem_enricher" in path else path.split("site-packages")[-1]
        print(f"{cum:7.2f} c  {name:<28} {short}:{line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

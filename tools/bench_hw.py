"""Замер производительности с паспортом железа: для раздела ВКР о методике."""

from __future__ import annotations

import json
import platform
import subprocess
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


def hardware() -> dict[str, str]:
    info: dict[str, str] = {
        "процессор": platform.processor() or "неизвестно",
        "ядер (логических)": str(__import__("os").cpu_count() or 1),
        "платформа": f"{platform.system()} {platform.release()}",
        "python": sys.version.split()[0],
    }
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Processor).Name; "
             "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,0)"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout.strip().splitlines()
        if out:
            info["процессор"] = out[0].strip()
        if len(out) > 1:
            info["память, ГБ"] = out[1].strip()
    except Exception:
        pass
    return info


def bench(events: list[dict], cache_size: int) -> tuple[float, int]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.cache_size = cache_size
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    started = time.perf_counter()
    for raw in events:
        pipeline.enrich_document("bench", raw)
    elapsed = time.perf_counter() - started
    pipeline.close()
    return elapsed, len(events)


def main() -> int:
    setup_logging(level="ERROR", fmt="json")
    print("=== характеристики машины ===")
    for key, value in hardware().items():
        print(f"  {key}: {value}")

    events = [json.loads(line) for line in
              (ROOT / "var" / "experiment" / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    warm = events[:8]
    bench(warm, 0)  # прогрев модели и кэшей

    print()
    print("=== скорость (272 события: набор дважды, без накопления истории) ===")
    doubled = events + events
    for cache_size, label in ((0, "без кэша классификации"), (4096, "с кэшем классификации")):
        elapsed, count = bench(doubled, cache_size)
        print(f"  {label:<24} {elapsed:6.2f} с   {count / elapsed:6.1f} событий/с   "
              f"{elapsed / count * 1000:6.1f} мс/событие")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

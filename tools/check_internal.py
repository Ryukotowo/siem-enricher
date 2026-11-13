"""Почему internal-события получают другой класс."""

import json
import sys
from pathlib import Path

sys.path.insert(0, "tools")
sys.path.insert(0, "src")

from generate_sample_events import build_events
from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.logging_setup import setup_logging

ROOT = Path(__file__).resolve().parents[1]
mapping = json.loads((ROOT / "config" / "sensitivity_labels.json").read_text(encoding="utf-8"))
print("карта классов:", mapping)

events = build_events(scenario="mixed", count=100)
internal = [e for e in events if (e.get("x_ground_truth") or {}).get("sensitivity") == "internal"]
print("internal-событий:", len(internal))
for event in internal[:6]:
    truth = event["x_ground_truth"]
    print("  ожидается internal:", truth.get("path"))

setup_logging(level="ERROR", fmt="json")
config = load_config(ROOT / "config" / "config.local.json")
pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
for event in internal[:6]:
    path = event["x_ground_truth"]["path"]
    if not path:
        print("  путь пуст, событие без файла")
        continue
    assessment = pipeline.classifier.predict(path)
    print(f"  получено {assessment.level.value:<13} метод {assessment.method:<10} {path}")
pipeline.close()

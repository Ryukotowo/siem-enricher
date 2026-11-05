"""Бинарные метрики на реальных данных: защищаемое против незащищаемого."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

DATA = ROOT / "var" / "datasets" / "names_1500_masked.jsonl"
POSITIVE = {"confidential", "secret"}


def main() -> int:
    from siem_enricher.config import load_config
    from siem_enricher.enricher import EnrichmentPipeline
    from siem_enricher.logging_setup import setup_logging

    setup_logging(level="ERROR", fmt="json")
    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    config = load_config(ROOT / "config" / "config.local.json")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)

    counts: Counter = Counter()
    by_dir: dict[str, Counter] = {}
    for row in rows:
        truth = row["level"] in POSITIVE
        predicted = pipeline.classifier.predict(row["path"]).level.value in POSITIVE
        if truth and predicted:
            counts["tp"] += 1
        elif truth:
            counts["fn"] += 1
        elif predicted:
            counts["fp"] += 1
        else:
            counts["tn"] += 1
        directory = str(row.get("directory") or "").split("\\")[1] if "\\" in str(row.get("directory")) else "?"
        stats = by_dir.setdefault(directory, Counter())
        stats["всего"] += 1
        if truth == predicted:
            stats["верно"] += 1
    pipeline.close()

    tp, fn, fp, tn = counts["tp"], counts["fn"], counts["fp"], counts["tn"]
    total = tp + fn + fp + tn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    print("защищаемое (confidential+secret) против остального:")
    print(f"  объектов: {total}  (защищаемых {tp + fn})")
    print(f"  полнота   {recall:.3f}")
    print(f"  точность  {precision:.3f}")
    print(f"  F1        {f1:.3f}")
    print(f"  ложных срабатываний {fpr:.3f}   ({fp} из {fp + tn})")
    print(f"  пропущено защищаемых: {fn}")
    print()
    print("по каталогам верхнего уровня:")
    for directory, stats in sorted(by_dir.items(), key=lambda item: -item[1]["всего"])[:8]:
        print(f"  {directory:<16} {stats['верно']:>4}/{stats['всего']:<4} "
              f"{stats['верно'] / stats['всего']:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

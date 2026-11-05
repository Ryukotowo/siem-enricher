"""Маскирование реальных имён файлов и оценка классификатора на них."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

SOURCE = ROOT / "var" / "datasets" / "names_1500.jsonl"
MASKED = ROOT / "var" / "datasets" / "names_1500_masked.jsonl"
REPORT = ROOT / "var" / "datasets" / "masking_report.json"

RULES = [
    ("организация", re.compile(r"(?i)\b(ООО|АО|ПАО|ЗАО|ИП|ОАО)\s*[«\"]?[^»\"\s,.;)0-9]{2,30}[»\"]?")),
    ("ФИО", re.compile(r"\b[А-ЯЁ][а-яё]{2,}(?:ов|ев|ёв|ин|ын|ский|цкий|ая|ко|ук|юк|енко|ич)\b")),
    ("ФИО-инициалы", re.compile(r"\b[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+")),
    ("ИНН", re.compile(r"\b\d{10,12}\b")),
    ("паспорт", re.compile(r"\b\d{4}\s?\d{6}\b")),
    ("телефон", re.compile(r"(?:\+7|8)[\s\-()]?\d{3}[\s\-()]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")),
    ("почта", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("номер договора", re.compile(r"(?i)(договор|контракт|счёт|счет)\D{0,6}\d{2,}")),
    ("сумма", re.compile(r"\b\d{1,3}(?:[  ]\d{3})+(?:[.,]\d{2})?\s?(?:руб|₽|RUB)?")),
]


def mask_text(text: str, counters: Counter) -> str:
    result = text
    for name, pattern in RULES:
        def replace(match: re.Match[str], rule: str = name) -> str:
            counters[rule] += 1
            return f"<{rule}_{counters[rule]}>"

        result = pattern.sub(replace, result)
    return result


def main() -> int:
    from siem_enricher.config import load_config
    from siem_enricher.enricher import EnrichmentPipeline
    from siem_enricher.logging_setup import setup_logging

    setup_logging(level="ERROR", fmt="json")
    rows = [json.loads(line) for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]

    counters: Counter = Counter()
    masked_rows = []
    samples = []
    for row in rows:
        before = row["name"]
        row["name"] = mask_text(row["name"], counters)
        row["path"] = mask_text(row["path"], counters)
        row["directory"] = mask_text(row["directory"], counters)
        masked_rows.append(row)
        if row["name"] != before and len(samples) < 5:
            samples.append({"было": before, "стало": row["name"]})

    MASKED.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in masked_rows) + "\n",
                      encoding="utf-8")

    config = load_config(ROOT / "config" / "config.local.json")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)
    truth = [row["level"] for row in masked_rows]
    predicted = [pipeline.classifier.predict(row["path"]).level.value for row in masked_rows]
    pipeline.close()

    correct = sum(1 for a, b in zip(truth, predicted) if a == b)
    confusion: Counter = Counter(zip(truth, predicted))
    per_class: dict[str, dict[str, float]] = {}
    for level in sorted(set(truth)):
        tp = confusion[(level, level)]
        total_truth = sum(count for (real, _), count in confusion.items() if real == level)
        total_pred = sum(count for (_, pred), count in confusion.items() if pred == level)
        per_class[level] = {
            "всего": total_truth,
            "полнота": round(tp / total_truth, 3) if total_truth else 0.0,
            "точность": round(tp / total_pred, 3) if total_pred else 0.0,
        }

    REPORT.write_text(json.dumps({
        "строк": len(rows),
        "замаскировано": dict(counters),
        "примеры": samples,
        "точность_класса": round(correct / len(truth), 3),
        "совпало": correct,
        "по_классам": per_class,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"строк: {len(rows)}, замаскировано: {dict(counters)}")
    for sample in samples:
        print(f"  было:  {sample['было']}")
        print(f"  стало: {sample['стало']}")
    print(f"точность класса на реальных данных: {correct / len(truth):.3f}")
    for level, stats in per_class.items():
        print(f"  {level:<15} n={stats['всего']:<4} полнота {stats['полнота']:.3f} точность {stats['точность']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

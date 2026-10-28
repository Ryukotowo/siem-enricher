"""Сборка датасета для обучения классификатора конфиденциальности.

Источники данных:

1. **Синтетический генератор** (``tools/generate_sample_events.py``) — даёт поток событий
   с эталонной разметкой (``x_ground_truth``), из которого извлекаются пары «путь -> класс»;
2. **внешний CSV** (``--from-csv``) с колонками ``text,label`` — формат датасета из НИР
   (например, ``filenames_mixed_dataset.csv``): текст — имя файла, метка — категория модели.

Результат: CSV с колонками ``path,text,label,source``, где ``text`` — то, что подаётся модели
(имя файла), ``label`` — категория модели (personal/commercial/...), ``path`` — полный путь
для справки и для гибридных правил, ``source`` — источник примера (csv/generator) для
раздельной оценки качества.

Примеры::

    python ml/training/build_dataset.py --out ml/data/processed/files.csv
    python ml/training/build_dataset.py --from-csv data/filenames_mixed_dataset.csv \
        --out ml/data/processed/files.csv
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from tools.generate_sample_events import build_events  # noqa: E402

#: Соответствие «класс конфиденциальности -> категория модели» (обратное к config/sensitivity_labels.json)
SENSITIVITY_TO_CATEGORY = {
    "public": "public",
    "internal": "official_internal",
    "confidential": "commercial",
    "secret": "personal",
}

#: Каталоги, добавляемые к «безымянным» именам файлов из внешнего CSV.
#: Важно: каталог не должен попадать под признаки размещения из fallback_rules
#: (иначе правила изменят класс, и метрика модели будет искажена).
CATEGORY_DIRECTORIES = {
    "personal": r"C:\HR",
    "commercial": r"C:\Коммерческая_тайна",
    "official_internal": r"C:\Внутренние_документы",
    "banking": r"C:\Бухгалтерия",
    "ip": r"C:\Projects",
    "public": r"C:\Public",
}

SAMPLES = ["mixed", "exfiltration", "ransomware", "benign"]


def collect_from_generator(scenarios: Iterable[str], count_per_scenario: int, seed: int) -> list[dict[str, str]]:
    """Собрать пары «путь -> категория» из синтетических событий."""
    rows: dict[str, str] = {}
    for scenario in scenarios:
        events = build_events(scenario=scenario, count=count_per_scenario, seed=seed)
        for event in events:
            ground_truth = event.get("x_ground_truth") or {}
            path = str(ground_truth.get("path") or "")
            sensitivity = str(ground_truth.get("sensitivity") or "internal")
            if path:
                rows[path] = SENSITIVITY_TO_CATEGORY.get(sensitivity, "official_internal")
            for item in (event.get("data", {}) or {}).get("files", []) or []:
                item_path = str(item.get("path") or "")
                if item_path:
                    rows.setdefault(item_path, SENSITIVITY_TO_CATEGORY.get(sensitivity, "official_internal"))
    return [{"path": path, "text": path.rsplit("\\", 1)[-1], "label": label, "source": "generator"}
            for path, label in sorted(rows.items())]


def collect_from_csv(source: Path, amplify: bool = True) -> list[dict[str, str]]:
    """Преобразовать внешний CSV ``text,label`` в общий формат датасета."""
    rows: list[dict[str, str]] = []
    # utf-8-sig: файлы, выгруженные pandas с BOM, читаются корректно
    with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "text" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise SystemExit(f"Ожидались колонки text,label в {source}; получено: {reader.fieldnames}")
        for record in reader:
            text = (record.get("text") or "").strip()
            label = (record.get("label") or "").strip()
            if not text or not label:
                continue
            directory = CATEGORY_DIRECTORIES.get(label, r"C:\Data")
            rows.append({"path": f"{directory}\\{text}", "text": text, "label": label, "source": "csv"})

    if amplify:
        # Дополняем датасет вариантами размещения: то же имя в разных каталогах,
        # чтобы гибридные правила и модель «видели» влияние каталога
        extra: list[dict[str, str]] = []
        for record in rows:
            for label, directory in CATEGORY_DIRECTORIES.items():
                if directory in record["path"]:
                    continue
                extra.append({"path": f"{directory}\\{record['text']}", "text": record["text"],
                              "label": label, "source": "csv"})
        rows.extend(extra)
    return rows


def write_dataset(rows: Sequence[dict[str, str]], destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda row: (row["label"], row["path"]))
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "text", "label", "source"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сборка датасета для классификатора конфиденциальности")
    parser.add_argument("--out", default="ml/data/processed/files.csv")
    parser.add_argument("--from-csv", default=None, help="Внешний CSV с колонками text,label")
    parser.add_argument("--scenarios", nargs="*", default=None, help=f"Сценарии генератора: {SAMPLES}")
    parser.add_argument("--count", type=int, default=120, help="Событий на сценарий")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-amplify", action="store_true", help="Не дублировать имена по каталогам")
    args = parser.parse_args(argv)

    rows: list[dict[str, str]] = []
    if args.from_csv:
        source = Path(args.from_csv)
        if not source.is_absolute():
            source = PROJECT_ROOT / source
        rows.extend(collect_from_csv(source, amplify=not args.no_amplify))
        print(f"Из внешнего CSV: {source}")

    scenarios = args.scenarios or SAMPLES
    rows.extend(collect_from_generator(scenarios, args.count, args.seed))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1

    destination = Path(args.out)
    if not destination.is_absolute():
        destination = PROJECT_ROOT / destination
    total = write_dataset(rows, destination)

    print(f"Записано примеров: {total} -> {destination}")
    print("Распределение по категориям:")
    for label, number in sorted(counts.items()):
        print(f"  {label:<20} {number}")
    print("\nДальше: python ml/training/train_transformer.py --dataset " + str(destination.relative_to(PROJECT_ROOT)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

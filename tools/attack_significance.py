"""Устойчивость к обходу (атака переименованием) и статистическая значимость различий."""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402
from tools.experiment_eval import confusion, quality  # noqa: E402

NEUTRAL_DIR = r"C:\Temp"

# как выглядит переименование: смысловое имя заменяется нейтральным, расширение сохраняется
RENAME = {
    "зарплатная_ведомость": "report_q3",
    "личные_дела_сотрудников": "data_01",
    "паспортные_данные": "table_02",
    "финансовый_отчет": "summary",
    "счет_фактура": "invoice_copy",
    "договор_поставки": "agreement",
    "диагнозы_пациентов": "records",
    "база_клиентов_crm_export": "export",
    "приказы_о_приеме": "order",
    "id_rsa": "notes",
    "пароли_от_сервисов": "backup",
    "ключи_подписи": "key_data",
    "отчет_о_работе": "progress",
    "техническое_задание": "spec",
    "регламент_информационной_безопасности": "policy",
    "черновик_письма": "draft",
    "общий_отчет_за_квартал": "quarter",
    "публичный_пресс_релиз": "news",
    "шаблон_письма_клиенту": "template",
}

REMOVABLE_PREFIX_RE = re.compile(r"(?i)^[e-z]:\\")


def neutral_name(path: str) -> str:
    """Нейтральное имя с сохранением расширения и каталога."""
    match = re.match(r"^(.*[\\/])([^\\/]+?)(\.[A-Za-zА-Яа-я0-9]{1,8})?$", path)
    if not match:
        return path
    prefix, stem, extension = match.group(1), match.group(2), match.group(3) or ""
    new_stem = None
    lowered = stem.lower()
    for key, value in RENAME.items():
        if key in lowered:
            new_stem = value
            break
    if new_stem is None:
        # имя без смыслового признака: заменяем на порядковый идентификатор
        new_stem = "file_" + str(abs(hash(stem)) % 97).zfill(2)
    return f"{prefix}{new_stem}{extension}"


def attack(raw: dict[str, Any], move: bool) -> dict[str, Any]:
    """Переименовать файлы события; при move=True также перенести в нейтральный каталог."""
    event = json.loads(json.dumps(raw, ensure_ascii=False))
    eventdata = ((event.get("data") or {}).get("win") or {}).get("eventdata") or {}

    def transform(value: str) -> str:
        renamed = neutral_name(value)
        if not move or REMOVABLE_PREFIX_RE.match(value):
            return renamed  # носитель сохраняем: переименование не меняет место
        name = renamed.replace("\\", "/").rsplit("/", 1)[-1]
        return f"{NEUTRAL_DIR}\\{name}"

    for key in ("targetFilename", "sourceFilename"):
        if isinstance(eventdata.get(key), str):
            eventdata[key] = transform(eventdata[key])
    plural = eventdata.get("targetFilenames")
    if isinstance(plural, str):
        eventdata["targetFilenames"] = ";".join(transform(part.strip()) for part in plural.split(";") if part.strip())
    return event


def build_pipelines(config) -> dict[str, EnrichmentPipeline]:
    rules_config = replace(config, ml=replace(config.ml, type="heuristic", hybrid_enabled=False))
    model_config = replace(config, ml=replace(config.ml, type="transformer", hybrid_enabled=False))
    return {
        "модель": EnrichmentPipeline.from_config(model_config, in_memory_store=True),
        "правила": EnrichmentPipeline.from_config(rules_config, in_memory_store=True),
        "гибрид": EnrichmentPipeline.from_config(config, in_memory_store=True),
    }


def predict(pipeline: EnrichmentPipeline, raw: dict[str, Any]) -> bool:
    event = pipeline.normalize("attack", raw)
    document = pipeline.enrich(event).document or {}
    decision = str(document.get("policy_decision", "allow"))
    severity = str(document.get("risk_severity", "low"))
    return decision in {"alert", "mask", "block"} or severity in {"high", "critical"}


def mcnemar(a: list[bool], b: list[bool], truth: list[bool]) -> dict[str, float]:
    """Критерий Мак-Немара для парных предсказаний двух детекторов."""
    b_count = sum(1 for x, y, t in zip(a, b, truth) if x != t and y == t)
    c_count = sum(1 for x, y, t in zip(a, b, truth) if x == t and y != t)
    if b_count + c_count == 0:
        return {"b": 0, "c": 0, "chi2": 0.0, "p": 1.0}
    chi2 = (abs(b_count - c_count) - 1) ** 2 / (b_count + c_count)
    p_value = math.erfc(math.sqrt(chi2 / 2))
    return {"b": b_count, "c": c_count, "chi2": round(chi2, 3), "p": round(p_value, 5)}


def bootstrap_diff(pred_a: list[bool], pred_b: list[bool], truth: list[bool],
                   metric: str, iterations: int = 2000, seed: int = 42) -> tuple[float, float]:
    """Бутстреп-интервал для разницы метрики между двумя детекторами."""
    rng = random.Random(seed)
    n = len(truth)
    values: list[float] = []
    for _ in range(iterations):
        indexes = [rng.randrange(n) for _ in range(n)]
        slice_truth = [truth[i] for i in indexes]
        stats_a = confusion([pred_a[i] for i in indexes], slice_truth)
        stats_b = confusion([pred_b[i] for i in indexes], slice_truth)
        values.append(quality(stats_b)[metric] - quality(stats_a)[metric])
    values.sort()
    low = values[int(0.025 * len(values))]
    high = values[int(0.975 * len(values)) - 1]
    return (round(low, 4), round(high, 4))


def summarize(predictions: list[bool], truth: list[bool]) -> dict[str, Any]:
    stats = confusion(predictions, truth)
    result = {"stats": stats, **{key: round(value, 4) for key, value in quality(stats).items()}}
    result["alerts"] = sum(predictions)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Устойчивость к переименованию и значимость различий")
    parser.add_argument("--dataset", default="var/experiment/dataset.jsonl")
    parser.add_argument("--out", default="var/experiment/report_attack")
    args = parser.parse_args()

    setup_logging(level="ERROR", fmt="json")
    config = load_config(PROJECT_ROOT / "config/config.local.json")
    original = [json.loads(line) for line in (PROJECT_ROOT / args.dataset).read_text(encoding="utf-8").splitlines() if line.strip()]
    renamed = [attack(raw, move=False) for raw in original]
    moved = [attack(raw, move=True) for raw in original]
    truth = [raw.get("x_label") == "incident" for raw in original]

    pipelines = build_pipelines(config)
    report: dict[str, Any] = {"total": len(original), "incidents": sum(truth), "variants": {}}
    predictions: dict[str, dict[str, list[bool]]] = {}

    for variant_name, dataset in (("исходный", original), ("переименование", renamed),
                                  ("переименование и перенос", moved)):
        variant: dict[str, Any] = {}
        for detector_name, pipeline in pipelines.items():
            # событие копируется: извлекатель не должен влиять на следующий детектор
            predicted = [predict(pipeline, json.loads(json.dumps(raw, ensure_ascii=False))) for raw in dataset]
            predictions.setdefault(detector_name, {})[variant_name] = predicted
            variant[detector_name] = summarize(predicted, truth)
        report["variants"][variant_name] = variant

    report["mcnemar"] = {
        "модель vs гибрид": mcnemar(predictions["модель"]["исходный"], predictions["гибрид"]["исходный"], truth),
        "правила vs гибрид": mcnemar(predictions["правила"]["исходный"], predictions["гибрид"]["исходный"], truth),
    }
    report["bootstrap_hybrid_minus_rules"] = {
        "precision": bootstrap_diff(predictions["правила"]["исходный"], predictions["гибрид"]["исходный"], truth, "precision"),
        "recall": bootstrap_diff(predictions["правила"]["исходный"], predictions["гибрид"]["исходный"], truth, "recall"),
        "fpr": bootstrap_diff(predictions["правила"]["исходный"], predictions["гибрид"]["исходный"], truth, "fpr"),
    }
    report["bootstrap_hybrid_minus_model"] = {
        "precision": bootstrap_diff(predictions["модель"]["исходный"], predictions["гибрид"]["исходный"], truth, "precision"),
        "recall": bootstrap_diff(predictions["модель"]["исходный"], predictions["гибрид"]["исходный"], truth, "recall"),
    }

    target = PROJECT_ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"событий: {report['total']}, инцидентов: {report['incidents']}\n")
    for variant_name, variant in report["variants"].items():
        print(f"--- {variant_name} ---")
        print(f"{'детектор':<12}{'полнота':>10}{'точность':>10}{'ложных':>9}{'F1':>8}")
        for detector_name, values in variant.items():
            print(f"{detector_name:<12}{values['recall']:>10.3f}{values['precision']:>10.3f}"
                  f"{values['fpr']:>9.3f}{values['f1']:>8.3f}")
        print()

    print("критерий Мак-Немара (исходный набор):")
    for name, values in report["mcnemar"].items():
        print(f"  {name}: b={values['b']}, c={values['c']}, chi2={values['chi2']}, p={values['p']}")
    print("\nбутстреп-интервал разницы (гибрид минус правила):")
    for name, values in report["bootstrap_hybrid_minus_rules"].items():
        print(f"  {name}: [{values[0]}; {values[1]}]")
    print(f"\nотчёт: {target.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

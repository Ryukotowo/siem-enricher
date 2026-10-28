"""Оценка эффекта обогащения: «как в SIEM» против «после обогащения»."""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher.pipeline import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402

BASELINE_LEVEL = 10
OUR_DECISIONS = {"alert", "mask", "block"}
PREVENT_DECISIONS = {"block", "mask"}


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Доверительный интервал Уилсона для доли."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def confusion(predicted: list[bool], truth: list[bool]) -> dict[str, int]:
    tp = sum(1 for p, t in zip(predicted, truth) if p and t)
    fp = sum(1 for p, t in zip(predicted, truth) if p and not t)
    fn = sum(1 for p, t in zip(predicted, truth) if not p and t)
    tn = sum(1 for p, t in zip(predicted, truth) if not p and not t)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def quality(stats: dict[str, int]) -> dict[str, float]:
    tp, fp, fn, tn = stats["tp"], stats["fp"], stats["fn"], stats["tn"]
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else 0.0
    return {
        "recall": recall, "precision": precision, "fpr": fpr,
        "specificity": 1 - fpr, "f1": f1, "accuracy": accuracy,
    }


def auc_roc(scores: list[float], truth: list[bool]) -> float:
    """Площадь под ROC-кривой (метод трапеций по порогам оценки риска)."""
    thresholds = sorted({0.0, 1.0, *scores})
    points: list[tuple[float, float]] = []
    for threshold in thresholds:
        predicted = [score >= threshold for score in scores]
        stats = confusion(predicted, truth)
        quality_stats = quality(stats)
        points.append((quality_stats["fpr"], quality_stats["recall"]))
    points.sort()
    area = 0.0
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        area += (x2 - x1) * (y1 + y2) / 2
    return area


def evaluate(dataset: Path, config_path: Path, force_heuristic: bool = False) -> dict[str, Any]:
    setup_logging(level="ERROR", fmt="json")
    config = load_config(config_path)
    if force_heuristic:
        try:
            config = replace(config, ml=replace(config.ml, type="heuristic", hybrid_enabled=False))
        except Exception as exc:  # noqa: BLE001
            print(f"не удалось переключить режим: {exc}")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)

    rows: list[dict[str, Any]] = []
    for line in dataset.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        event = pipeline.normalize("experiment", raw)
        enriched = pipeline.enrich(event)
        document = enriched.document or {}
        rows.append({
            "kind": raw.get("x_kind", "?"),
            "incident": raw.get("x_label") == "incident",
            "rule_level": int((raw.get("rule") or {}).get("level", 0)),
            "risk": float(document.get("risk_score", 0.0)),
            "severity": str(document.get("risk_severity", "low")),
            "decision": str(document.get("policy_decision", "allow")),
            "sensitivity": str(document.get("data_sensitivity", "unknown")),
            "confidence": float(document.get("sensitivity_confidence", 0.0)),
            "rules": list(document.get("policy_rule_ids") or []),
        })

    truth = [row["incident"] for row in rows]
    baseline = [row["rule_level"] >= BASELINE_LEVEL for row in rows]
    ours = [row["decision"] in OUR_DECISIONS or row["severity"] in {"high", "critical"} for row in rows]
    prevention = [row["decision"] in PREVENT_DECISIONS for row in rows]

    base_stats = confusion(baseline, truth)
    our_stats = confusion(ours, truth)
    base_quality = quality(base_stats)
    our_quality = quality(our_stats)

    incidents = sum(truth)
    benign = len(truth) - incidents
    prevented = sum(1 for row, flag in zip(rows, prevention) if flag and row["incident"])
    prevention_rate = prevented / incidents if incidents else 0.0
    baseline_alerts = sum(baseline)
    our_alerts = sum(ours)
    reduction = (baseline_alerts - our_alerts) / baseline_alerts if baseline_alerts else 0.0

    recall_ci = wilson(our_stats["tp"], our_stats["tp"] + our_stats["fn"])
    precision_ci = wilson(our_stats["tp"], our_stats["tp"] + our_stats["fp"])
    base_recall_ci = wilson(base_stats["tp"], base_stats["tp"] + base_stats["fn"])
    prevention_ci = wilson(prevented, incidents)

    # Разбивка по типам случаев
    by_kind: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = by_kind.setdefault(row["kind"], {
            "kind": row["kind"], "total": 0, "incident": row["incident"],
            "baseline_alert": 0, "our_alert": 0, "prevented": 0,
            "level": row["rule_level"],
        })
        item["total"] += 1
        item["baseline_alert"] += 1 if row["rule_level"] >= BASELINE_LEVEL else 0
        item["our_alert"] += 1 if (row["decision"] in OUR_DECISIONS or row["severity"] in {"high", "critical"}) else 0
        item["prevented"] += 1 if row["decision"] in PREVENT_DECISIONS else 0

    # Кривая «порог риска → полнота и доля ложных»
    curve: list[dict[str, float]] = []
    for threshold in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9):
        stats = confusion([row["risk"] >= threshold for row in rows], truth)
        stats_quality = quality(stats)
        curve.append({
            "threshold": threshold,
            "recall": round(stats_quality["recall"], 4),
            "fpr": round(stats_quality["fpr"], 4),
            "precision": round(stats_quality["precision"], 4),
        })

    mode = "правила" if force_heuristic else "гибрид"
    return {
        "mode": mode,
        "total": len(rows),
        "incidents": incidents,
        "benign": benign,
        "baseline": {"stats": base_stats, **{k: round(v, 4) for k, v in base_quality.items()},
                     "alerts": baseline_alerts, "recall_ci": [round(v, 4) for v in base_recall_ci]},
        "proposed": {"stats": our_stats, **{k: round(v, 4) for k, v in our_quality.items()},
                     "alerts": our_alerts,
                     "recall_ci": [round(v, 4) for v in recall_ci],
                     "precision_ci": [round(v, 4) for v in precision_ci]},
        "prevented": prevented,
        "prevention_rate": round(prevention_rate, 4),
        "prevention_ci": [round(v, 4) for v in prevention_ci],
        "alert_reduction": round(reduction, 4),
        "auc": round(auc_roc([row["risk"] for row in rows], truth), 4),
        "curve": curve,
        "by_kind": sorted(by_kind.values(), key=lambda item: (item["incident"], item["kind"])),
        "rows": rows,
    }


def to_markdown(result: dict[str, Any]) -> str:
    base = result["baseline"]
    ours = result["proposed"]
    lines = [
        f"# Оценка эффекта обогащения ({result['mode']})",
        "",
        f"Событий: {result['total']}; инцидентов: {result['incidents']}; "
        f"легитимных: {result['benign']}",
        "",
        "| Показатель | Как в SIEM (уровень ≥ 10) | После обогащения |",
        "|---|---|---|",
        f"| Полнота обнаружения (recall) | {base['recall']:.3f} "
        f"[{base['recall_ci'][0]:.3f}–{base['recall_ci'][1]:.3f}] | **{ours['recall']:.3f}** "
        f"[{ours['recall_ci'][0]:.3f}–{ours['recall_ci'][1]:.3f}] |",
        f"| Точность (precision) | {base['precision']:.3f} | **{ours['precision']:.3f}** "
        f"[{ours['precision_ci'][0]:.3f}–{ours['precision_ci'][1]:.3f}] |",
        f"| Доля ложных срабатываний | {base['fpr']:.3f} | **{ours['fpr']:.3f}** |",
        f"| F1-мера | {base['f1']:.3f} | **{ours['f1']:.3f}** |",
        f"| Тревог на {result['total']} событий | {base['alerts']} | {ours['alerts']} "
        f"({result['alert_reduction'] * 100:+.1f} %) |",
        f"| Инцидентов предотвращено (блокировка/маскирование) | 0 | **{result['prevented']} "
        f"из {result['incidents']}** ({result['prevention_rate'] * 100:.1f} %) |",
        f"| AUC оценки риска | — | {result['auc']:.3f} |",
        "",
        "## По типам случаев",
        "",
        "| Тип случая | Уровень правила | Метка | Всего | SIEM реагирует | Обогащение реагирует | Предотвращено |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in result["by_kind"]:
        lines.append(
            f"| {item['kind']} | {item['level']} | {'инцидент' if item['incident'] else 'легитимно'} | "
            f"{item['total']} | {item['baseline_alert']} | {item['our_alert']} | {item['prevented']} |"
        )
    lines += [
        "",
        "## Порог оценки риска",
        "",
        "| Порог | Полнота | Доля ложных | Точность |",
        "|---|---|---|---|",
    ]
    for point in result["curve"]:
        lines.append(f"| {point['threshold']:.2f} | {point['recall']:.3f} | "
                     f"{point['fpr']:.3f} | {point['precision']:.3f} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Оценка эффекта обогащения событий")
    parser.add_argument("--dataset", default="var/experiment/dataset.jsonl")
    parser.add_argument("--config", default="config/config.local.json")
    parser.add_argument("--out", default="var/experiment/report")
    parser.add_argument("--force-heuristic", action="store_true")
    args = parser.parse_args()

    result = evaluate(PROJECT_ROOT / args.dataset, PROJECT_ROOT / args.config, args.force_heuristic)
    target = PROJECT_ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    (target.with_suffix(".json")).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (target.with_suffix(".md")).write_text(to_markdown(result), encoding="utf-8")

    base, ours = result["baseline"], result["proposed"]
    print(f"режим: {result['mode']}; событий {result['total']} "
          f"(инцидентов {result['incidents']}, легитимных {result['benign']})")
    print(f"{'показатель':<34}{'SIEM':>10}{'обогащение':>14}")
    print(f"{'полнота':<34}{base['recall']:>10.3f}{ours['recall']:>14.3f}")
    print(f"{'точность':<34}{base['precision']:>10.3f}{ours['precision']:>14.3f}")
    print(f"{'доля ложных срабатываний':<34}{base['fpr']:>10.3f}{ours['fpr']:>14.3f}")
    print(f"{'F1':<34}{base['f1']:>10.3f}{ours['f1']:>14.3f}")
    print(f"{'тревог':<34}{base['alerts']:>10}{ours['alerts']:>14}")
    print(f"{'предотвращено инцидентов':<34}{0:>10}{result['prevented']:>14}")
    print(f"{'AUC оценки риска':<34}{'—':>10}{result['auc']:>14.3f}")
    print(f"отчёт: {target.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

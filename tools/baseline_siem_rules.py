"""Сравнение с типовым набором правил SIEM на том же наборе событий."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from tools.experiment_eval import confusion, quality, wilson  # noqa: E402

SENSITIVE_WORDS = re.compile(
    r"(?i)(зарплат|ведомост|паспорт|снилс|анкет|договор|клиент|счет|счёт|отчет|отчёт|"
    r"финанс|диагноз|медиц|личное|личные|приказ|payroll|salary|invoice|contract|customer)"
)
SECRET_EXT = re.compile(r"(?i)\.(kdbx|pem|key|env|pfx|p12)$")
PROTECTED_DIR = re.compile(r"(?i)(\\hr\\|\\бухгалтер|\\юридическ|\\клиент|\\медицин|\\finance|\\legal)")
REMOVABLE = re.compile(r"(?i)^[e-z]:\\")
SEND_ACTIONS = {"upload", "send"}
MOVE_ACTIONS = {"copy", "move", "archive"}


def extract(raw: dict[str, Any]) -> dict[str, Any]:
    """Достать из события то, на что опираются типовые правила."""
    data = raw.get("data") or {}
    eventdata = (data.get("win") or {}).get("eventdata") or {}
    paths: list[str] = []
    for key in ("targetFilename", "sourceFilename"):
        value = eventdata.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    plural = eventdata.get("targetFilenames")
    if isinstance(plural, str):
        paths.extend(part.strip() for part in plural.split(";") if part.strip())

    external = bool(eventdata.get("destinationIp") or eventdata.get("destinationUrl"))
    removable = any(REMOVABLE.search(path) for path in paths)
    return {
        "action": str(data.get("action") or "unknown").lower(),
        "paths": paths,
        "names": [Path(path.replace("\\", "/")).name for path in paths],
        "external": external,
        "removable": removable,
        "files_count": len(paths),
        "level": int((raw.get("rule") or {}).get("level", 0)),
        "incident": raw.get("x_label") == "incident",
    }


def rules(features: dict[str, Any]) -> dict[str, bool]:
    """Типовые правила: имя правила -> сработало ли; критичные помечены отдельно."""
    action = features["action"]
    names = " ".join(features["names"])
    joined = " ".join(features["paths"])
    fire = {
        "R1 ключевое слово в имени": bool(SENSITIVE_WORDS.search(names)) and action in (SEND_ACTIONS | MOVE_ACTIONS),
        "R2 защищённое расширение": any(SECRET_EXT.search(name) for name in features["names"]),
        "R3 защищённый каталог": bool(PROTECTED_DIR.search(joined)) and action in (SEND_ACTIONS | MOVE_ACTIONS | {"read"}),
        "R4 отправка во внешний адрес": action in SEND_ACTIONS and features["external"],
        "R5 шифрование": action == "encrypt",
        "R6 архив с внешним получателем": action == "archive" and (features["external"] or features["removable"]),
        "R7 массовое копирование": features["files_count"] >= 10,
        "R8 уровень правила >= 10": features["level"] >= 10,
        "R9 копирование на съёмный носитель": action in MOVE_ACTIONS and features["removable"],
        "R10 переименование с высоким уровнем": action == "rename" and features["level"] >= 10,
    }
    return fire


CRITICAL = {
    "R2 защищённое расширение", "R4 отправка во внешний адрес", "R5 шифрование",
    "R6 архив с внешним получателем", "R7 массовое копирование", "R9 копирование на съёмный носитель",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Сравнение с типовым набором правил SIEM")
    parser.add_argument("--dataset", default="var/experiment/dataset.jsonl")
    parser.add_argument("--out", default="var/experiment/report_baseline_rules")
    args = parser.parse_args()

    rows = [extract(json.loads(line)) for line in (PROJECT_ROOT / args.dataset).read_text(encoding="utf-8").splitlines() if line.strip()]
    truth = [row["incident"] for row in rows]
    fired = [rules(row) for row in rows]

    alert_only = [any(rule.values()) for rule in fired]
    with_block = [any(value for name, value in rule.items() if name in CRITICAL) for rule in fired]

    def summary(predicted: list[bool]) -> dict[str, Any]:
        stats = confusion(predicted, truth)
        result = {"stats": stats, **{key: round(value, 4) for key, value in quality(stats).items()}}
        result["alerts"] = sum(predicted)
        result["prevented"] = stats["tp"]
        return result

    baseline_alert = summary(alert_only)
    baseline_block = summary(with_block)
    incidents = sum(truth)

    report = {
        "total": len(rows),
        "incidents": incidents,
        "benign": len(truth) - incidents,
        "rules_alert_only": baseline_alert,
        "rules_with_block": baseline_block,
        "per_rule": {
            name: sum(1 for rule in fired if rule[name]) for name in fired[0]
        },
        "recall_ci": [round(v, 4) for v in wilson(baseline_alert["stats"]["tp"], incidents)],
        "precision_ci": [round(v, 4) for v in wilson(baseline_alert["stats"]["tp"],
                                                     baseline_alert["stats"]["tp"] + baseline_alert["stats"]["fp"])],
    }

    target = PROJECT_ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"событий: {report['total']} (инцидентов {incidents}, легитимных {report['benign']})")
    header = f"{'показатель':<26}{'оповещение':>14}{'с блокировкой':>16}"
    print(header)
    for key, label in (("recall", "полнота"), ("precision", "точность"), ("fpr", "доля ложных"),
                       ("f1", "F1"), ("alerts", "тревог"), ("prevented", "предотвращено")):
        left = baseline_alert[key]
        right = baseline_block[key]
        print(f"{label:<26}{left:>14}{right:>16}")
    print("\nсрабатывания по правилам:")
    for name, count in sorted(report["per_rule"].items()):
        print(f"  {name:<42}{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

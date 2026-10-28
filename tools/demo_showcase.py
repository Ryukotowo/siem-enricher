"""Наглядная демонстрация: события до и после обогащения."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#d97706",
    "medium": "#b7950b",
    "low": "#2e7d32",
}
LEVEL_LABELS = {
    "secret": "секретно",
    "confidential": "конфиденциально",
    "internal": "служебно",
    "public": "открыто",
    "unknown": "не определено",
}
DECISION_LABELS = {
    "block": "блокировка",
    "mask": "маскирование",
    "alert": "оповещение",
    "tag": "пометка",
    "allow": "разрешено",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            items.append(json.loads(line))
    return items


def first_file(event: dict[str, Any]) -> str:
    files = event.get("files") or []
    if files and isinstance(files[0], dict):
        return str(files[0].get("path") or files[0].get("name") or "—")
    return "—"


def summarize(raw: dict[str, Any], enriched: dict[str, Any]) -> dict[str, Any]:
    files = enriched.get("files") or []
    path = "—"
    if files and isinstance(files[0], dict):
        path = str(files[0].get("path") or files[0].get("name") or "—")
    return {
        "id": enriched.get("event_id") or raw.get("id") or "—",
        "action": enriched.get("action") or raw.get("action") or "—",
        "path": path,
        "level": enriched.get("data_sensitivity") or "—",
        "confidence": enriched.get("sensitivity_confidence"),
        "method": enriched.get("sensitivity_method") or "—",
        "depth": enriched.get("provenance_depth"),
        "external": enriched.get("external_destinations_count"),
        "risk": enriched.get("risk_score"),
        "severity": enriched.get("risk_severity") or "—",
        "decision": enriched.get("policy_decision") or "—",
        "rules": enriched.get("policy_rule_ids") or [],
        "reason": enriched.get("sensitivity_reason") or "",
        "duration": (enriched.get("enrichment") or {}).get("duration_ms"),
    }


def print_table(rows: list[dict[str, Any]]) -> None:
    print(f"{'#':>2}  {'действие':<9} {'файл':<34} {'класс':<15} {'риск':>5} {'уровень':<9} "
          f"{'решение':<12} правила")
    print("-" * 118)
    for index, row in enumerate(rows, start=1):
        path = row["path"] if len(row["path"]) <= 33 else "…" + row["path"][-32:]
        risk = f"{row['risk']:.2f}" if isinstance(row["risk"], (int, float)) else "—"
        rules = ",".join(row["rules"]) or "—"
        print(f"{index:>2}  {row['action']:<9} {path:<34} {LEVEL_LABELS.get(row['level'], row['level']):<15} "
              f"{risk:>5} {row['severity']:<9} {DECISION_LABELS.get(row['decision'], row['decision']):<12} {rules}")


def build_html(rows: list[dict[str, Any]], source: str) -> str:
    counters: dict[str, int] = {}
    severities: dict[str, int] = {}
    for row in rows:
        counters[row["level"]] = counters.get(row["level"], 0) + 1
        severities[row["severity"]] = severities.get(row["severity"], 0) + 1

    summary = " ".join(
        f'<span class="pill">{html.escape(LEVEL_LABELS.get(k, k))}: <b>{v}</b></span>'
        for k, v in sorted(counters.items(), key=lambda item: -item[1])
    )
    severity_summary = " ".join(
        f'<span class="pill sev" style="border-color:{SEVERITY_COLORS.get(k, "#666")};'
        f'color:{SEVERITY_COLORS.get(k, "#666")}">{k}: <b>{v}</b></span>'
        for k, v in sorted(severities.items(), key=lambda item: -item[1])
    )

    cards = []
    for index, row in enumerate(rows, start=1):
        colour = SEVERITY_COLORS.get(row["severity"], "#666")
        risk = f"{row['risk']:.2f}" if isinstance(row["risk"], (int, float)) else "—"
        conf = f"{row['confidence']:.2f}" if isinstance(row["confidence"], (int, float)) else "—"
        rules = "".join(f'<span class="rule">{html.escape(str(r))}</span>' for r in row["rules"]) or "—"
        cards.append(f"""
    <article class="card">
      <header>
        <span class="num">{index}</span>
        <code class="action">{html.escape(row['action'])}</code>
        <span class="badge" style="background:{colour}">{html.escape(row['severity'])}</span>
        <span class="risk">риск {risk}</span>
      </header>
      <p class="path">{html.escape(row['path'])}</p>
      <dl>
        <div><dt>класс</dt><dd class="level">{html.escape(LEVEL_LABELS.get(row['level'], row['level']))}
             <small>уверенность {conf} · {html.escape(row['method'])}</small></dd></div>
        <div><dt>происхождение</dt><dd>глубина цепочки {row['depth']}, внешних адресатов {row['external']}</dd></div>
        <div><dt>решение</dt><dd>{html.escape(DECISION_LABELS.get(row['decision'], row['decision']))}</dd></div>
        <div><dt>правила</dt><dd>{rules}</dd></div>
        <div><dt>обоснование</dt><dd>{html.escape(row['reason'] or '—')}</dd></div>
        <div><dt>время</dt><dd>{row['duration']:.1f} мс</dd></div>
      </dl>
    </article>""")

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Сервис обогащения событий SIEM — демонстрация</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 28px 32px;
         background: #f6f7f9; color: #1b1f24; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #5b6470; font-size: 13px; margin-bottom: 18px; }}
  .pill {{ display: inline-block; padding: 3px 10px; margin: 0 6px 6px 0; border-radius: 999px;
           background: #fff; border: 1px solid #d6dae0; font-size: 12px; }}
  .pill.sev {{ border-width: 1px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px;
           margin-top: 18px; }}
  .card {{ background: #fff; border: 1px solid #e2e5ea; border-radius: 10px; padding: 14px 16px;
           box-shadow: 0 1px 2px rgba(16,24,40,.05); }}
  .card header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
  .num {{ width: 22px; height: 22px; border-radius: 50%; background: #eef1f5; color: #4a5460;
          font-size: 12px; display: inline-flex; align-items: center; justify-content: center; }}
  .action {{ background: #eef1f5; padding: 2px 7px; border-radius: 5px; font-size: 12px; }}
  .badge {{ color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 999px; text-transform: uppercase; }}
  .risk {{ margin-left: auto; font-size: 12px; color: #5b6470; }}
  .path {{ font-family: Consolas, monospace; font-size: 12px; background: #f8f9fb; padding: 6px 8px;
           border-radius: 6px; word-break: break-all; margin: 0 0 10px; }}
  dl {{ margin: 0; font-size: 12.5px; display: grid; gap: 5px; }}
  dl div {{ display: grid; grid-template-columns: 108px 1fr; gap: 8px; }}
  dt {{ color: #6b7480; }}
  dd {{ margin: 0; }}
  dd.level {{ font-weight: 600; }}
  small {{ color: #6b7480; font-weight: 400; }}
  .rule {{ display: inline-block; background: #eef1f5; border-radius: 4px; padding: 1px 6px;
           margin-right: 4px; font-size: 11.5px; }}
</style>
</head>
<body>
  <h1>Сервис обогащения событий SIEM</h1>
  <div class="sub">Демонстрация: {len(rows)} событий обработано конвейером «извлечение → классификация →
    происхождение → риск → политики». Источник: {html.escape(source)}</div>
  <div>{summary}</div>
  <div>{severity_summary}</div>
  <div class="grid">{''.join(cards)}</div>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Демонстрация «до/после» обогащения событий")
    parser.add_argument("--input", default="var/demo/demo.jsonl")
    parser.add_argument("--enriched", default="var/demo/enriched.jsonl")
    parser.add_argument("--html", default="var/demo/report.html")
    args = parser.parse_args()

    raw_events = {item.get("id"): item for item in load_jsonl(Path(args.input))}
    enriched_events = load_jsonl(Path(args.enriched))
    rows = [summarize(raw_events.get(item.get("event_id"), {}), item) for item in enriched_events]
    rows = [row for row in rows if row["level"] != "—"]

    print_table(rows)
    durations = [row["duration"] for row in rows if isinstance(row["duration"], (int, float))]
    if durations:
        print(f"\nобработано {len(rows)} событий; среднее время {sum(durations) / len(durations):.1f} мс")

    target = Path(args.html)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_html(rows, Path(args.input).name), encoding="utf-8")
    print(f"отчёт: {target.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

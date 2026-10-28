"""Засев индекса событий с актуальными отметками времени."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from tools.generate_sample_events import build_events  # noqa: E402
from tools.seed_opensearch import index_events, install_templates, wait_for_cluster  # noqa: E402

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_timestamp(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def shift_events(events: list[dict], reference: datetime | None = None,
                 window_minutes: float = 10.0) -> timedelta:
    """Уложить поток в последние ``window_minutes`` минут, сохранив порядок событий."""
    reference = reference or datetime.now(tz=timezone.utc)
    stamps = [parse_timestamp(event["@timestamp"]) for event in events if event.get("@timestamp")]
    if not stamps:
        return timedelta(0)

    earliest, latest = min(stamps), max(stamps)
    span = (latest - earliest).total_seconds() or 1.0
    window = max(window_minutes, 1.0) * 60.0
    start = reference - timedelta(seconds=window)

    for event in events:
        if not event.get("@timestamp"):
            continue
        offset = (parse_timestamp(event["@timestamp"]) - earliest).total_seconds()
        moment = start + timedelta(seconds=offset / span * window)
        event["@timestamp"] = moment.strftime(TIME_FORMAT)
    return reference - latest


def main() -> int:
    parser = argparse.ArgumentParser(description="Засев SIEM событиями с текущими отметками времени")
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--scenario", default="mixed",
                        choices=["benign", "exfiltration", "ransomware", "mixed"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--window-minutes", type=float, default=10.0,
                        help="Уложить поток в последние N минут (по умолчанию 10)")
    parser.add_argument("--dump", default="", help="Куда сохранить сдвинутый поток (JSONL)")
    args = parser.parse_args()

    if not args.no_wait and not wait_for_cluster(args.url):
        print("!! кластер не готов")
        return 1
    if not install_templates(args.url):
        return 1

    events = build_events(scenario=args.scenario, count=args.count, seed=args.seed)
    shift_events(events, window_minutes=args.window_minutes)
    print(f"поток уложен в последние {args.window_minutes:g} мин (событий: {len(events)})")

    if args.dump:
        target = Path(args.dump)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(f"поток сохранён: {target}")

    loaded = index_events(args.url, events)
    return 0 if loaded else 1


if __name__ == "__main__":
    raise SystemExit(main())

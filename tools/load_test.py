"""Нагрузочная проверка: публикация событий в Kafka и замер сквозной обработки.

Запуск внутри образа сервиса:

    docker compose run --rm --entrypoint python enricher \
        tools/load_test.py --count 10000 --batch 500

Скрипт публикует события, ждёт, пока сервис их обработает, и печатает отчёт:
пропускную способность, потери и квантили задержки из гистограммы Prometheus.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

from generate_sample_events import build_events  # noqa: E402

REPORT = ROOT / "var" / "load_report.json"


def metrics(base: str) -> str:
    return urllib.request.urlopen(f"{base}/metrics", timeout=30).read().decode()


def counter(text: str, name: str) -> float:
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            try:
                return float(line.rsplit(" ", 1)[1])
            except ValueError:
                continue
    return 0.0


def histogram(text: str, name: str) -> tuple[float, float, dict[float, float]]:
    total = counter(text, name + "_count")
    total_sum = counter(text, name + "_sum")
    buckets: dict[float, float] = {}
    for line in text.splitlines():
        if line.startswith(name + "_bucket"):
            label = line.split("le=\"", 1)[1].split('"', 1)[0]
            value = float(line.rsplit(" ", 1)[1])
            buckets[float(label)] = value
    return total, total_sum, buckets


def quantile(buckets: dict[float, float], total: float, share: float) -> float | None:
    if not total:
        return None
    target = total * share
    for bound in sorted(buckets):
        if buckets[bound] >= target:
            return bound if bound != float("inf") else None
    return None


async def publish(events: list[dict], bootstrap: str, topic: str) -> float:
    from aiokafka import AIOKafkaProducer

    producer = AIOKafkaProducer(bootstrap_servers=bootstrap,
                                value_serializer=lambda value: json.dumps(
                                    value, ensure_ascii=False).encode("utf-8"))
    await producer.start()
    started = time.perf_counter()
    try:
        for event in events:
            await producer.send_and_wait(topic, event)
    finally:
        await producer.stop()
    return time.perf_counter() - started


def build_batch(batch: int, offset: int, scenario: str) -> list[dict]:
    events = build_events(scenario=scenario, count=batch)
    for position, event in enumerate(events, 1):
        event["id"] = f"{1700000000 + offset + 1}.{position:06d}"
    return events


async def main() -> int:
    parser = argparse.ArgumentParser(description="Нагрузочная проверка через Kafka")
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--bootstrap", default="redpanda:9092")
    parser.add_argument("--topic", default="siem.raw.events")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--scenario", default="mixed")
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args()

    before_text = metrics(args.base)
    before = counter(before_text, "siem_enricher_events_enriched_total")

    sent = 0
    publish_started = time.perf_counter()
    offset = 0
    while sent < args.count:
        size = min(args.batch, args.count - sent)
        events = build_batch(size, offset, args.scenario)
        offset += 1
        await publish(events, args.bootstrap, args.topic)
        sent += size
    publish_time = time.perf_counter() - publish_started

    deadline = time.time() + args.timeout
    processed = before
    while time.time() < deadline:
        await asyncio.sleep(1.0)
        processed = counter(metrics(args.base), "siem_enricher_events_enriched_total")
        if processed - before >= sent:
            break
    drain_time = time.perf_counter() - publish_started

    after_text = metrics(args.base)
    total, total_sum, buckets = histogram(after_text, "siem_enricher_enrichment_duration_seconds")
    report = {
        "событий": sent,
        "публикация_с": round(publish_time, 2),
        "до_готовности_с": round(drain_time, 2),
        "обработано": int(processed - before),
        "потери": int(sent - (processed - before)),
        "событий_в_секунду": round(sent / drain_time, 1) if drain_time else 0,
        "публикация_в_секунду": round(sent / publish_time, 1) if publish_time else 0,
        "средняя_задержка_мс": round(total_sum / total * 1000, 2) if total else None,
        "p50_мс": quantile(buckets, total, 0.5),
        "p95_мс": quantile(buckets, total, 0.95),
        "p99_мс": quantile(buckets, total, 0.99),
        "обработано_всего_за_сеанс": int(total),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== нагрузочная проверка ===")
    for key, value in report.items():
        print(f"  {key}: {value}")
    return 0 if report["потери"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

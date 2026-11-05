"""Живой поток Kafka: чтение сырых событий, обогащение, запись результата обратно."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.enricher import EnrichmentPipeline  # noqa: E402
from siem_enricher.logging_setup import setup_logging  # noqa: E402

INPUT_TOPIC = "siem-events"
OUTPUT_TOPIC = "siem-enriched"
BOOTSTRAP = "localhost:9092"
GROUP = "siem-enricher-demo"
OUTPUT_FILE = ROOT / "var" / "screens" / "kafka_enriched.jsonl"
LIMIT = 136


async def main() -> int:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    setup_logging(level="ERROR", fmt="json")
    config = load_config(ROOT / "config" / "config.kafka.json")
    config = config.__class__.from_dict(
        {**json.loads((ROOT / "config" / "config.kafka.json").read_text(encoding="utf-8")),
         "provenance": {**json.loads((ROOT / "config" / "config.kafka.json").read_text(encoding="utf-8"))["provenance"],
                        "sqlite_path": str(ROOT / "var" / "state" / "provenance.db")}},
        path=ROOT / "config" / "config.kafka.json",
    )
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=True)

    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=5000,
    )
    producer = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP, acks="all")

    await consumer.start()
    await producer.start()
    OUTPUT_FILE.write_text("", encoding="utf-8")

    processed = 0
    decisions: dict[str, int] = {}
    classes: dict[str, int] = {}
    try:
        async for message in consumer:
            raw = json.loads(message.value.decode("utf-8"))
            document = pipeline.enrich(pipeline.normalize(INPUT_TOPIC, raw)).document or {}
            slim = {key: value for key, value in document.items()
                    if key not in ("raw_event", "files", "provenance_chain", "provenance_chains")}
            slim["files_count"] = len(document.get("files") or [])
            document = slim
            payload = json.dumps(document, ensure_ascii=False, default=str).encode("utf-8")
            await producer.send_and_wait(OUTPUT_TOPIC, payload)
            with OUTPUT_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(document, ensure_ascii=False, default=str) + "\n")
            processed += 1
            decision = str(document.get("policy_decision", "allow"))
            decisions[decision] = decisions.get(decision, 0) + 1
            sensitivity = str(document.get("data_sensitivity", "unknown"))
            classes[sensitivity] = classes.get(sensitivity, 0) + 1
            if processed % 20 == 0:
                print(f"  обработано: {processed}")
            if processed >= LIMIT:
                break
        await consumer.commit()
    finally:
        await producer.stop()
        await consumer.stop()
        pipeline.close()

    print()
    print(f"прочитано из {INPUT_TOPIC}: {processed}")
    print(f"записано в {OUTPUT_TOPIC}: {processed}")
    print(f"по решениям: {decisions}")
    print(f"по классам: {classes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

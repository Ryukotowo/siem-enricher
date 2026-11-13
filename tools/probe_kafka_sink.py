"""Проверка запуска Kafka-приёмника с разными настройками."""

import asyncio
import sys

sys.path.insert(0, "/app/src")


async def main() -> int:
    from siem_enricher.connectors.kafka import KafkaSink

    for options in (
        {"bootstrap_servers": "redpanda:9092", "topic": "siem.enriched.events",
         "acks": 1, "wait_ack": False},
        {"bootstrap_servers": "redpanda:9092", "topic": "siem.enriched.events",
         "acks": "all", "wait_ack": False},
    ):
        sink = KafkaSink(options)
        try:
            await sink.start()
            document = {"event_id": "probe", "data_sensitivity": "internal"}
            sent = await sink.send(document)
            await sink.flush()
            print("вариант", options["acks"], "-> старт ок, отправка", sent)
        except Exception as exc:  # noqa: BLE001
            print("вариант", options["acks"], "-> ошибка:", type(exc).__name__, exc)
        finally:
            await sink.stop()
    return 0


raise SystemExit(asyncio.run(main()))

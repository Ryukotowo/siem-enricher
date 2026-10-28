"""Утилита работы с Kafka: публикация событий и просмотр результатов."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

INSTALL_HINT = "Для работы с Kafka требуется aiokafka: pip install 'siem-enricher[kafka]'"


def read_documents(path: Path) -> list[dict[str, Any]]:
    """Прочитать события из JSONL-файла."""
    documents: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(document, dict):
                documents.append(document)
    return documents


async def publish(args: argparse.Namespace) -> int:
    try:
        from aiokafka import AIOKafkaProducer
    except ImportError:
        print(INSTALL_HINT, file=sys.stderr)
        return 2

    documents = read_documents(Path(args.input))
    if not documents:
        print(f"Нет событий для публикации в {args.input}", file=sys.stderr)
        return 1

    producer = AIOKafkaProducer(
        bootstrap_servers=args.bootstrap,
        acks=args.acks,
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"),
    )
    await producer.start()
    sent = 0
    try:
        for document in documents:
            await producer.send_and_wait(args.topic, document)
            sent += 1
            if args.rate and sent % 100 == 0:
                await asyncio.sleep(0.1)
    finally:
        await producer.stop()
    print(f"Опубликовано событий: {sent} -> {args.topic} ({args.bootstrap})")
    return 0


async def consume(args: argparse.Namespace) -> int:
    try:
        from aiokafka import AIOKafkaConsumer
    except ImportError:
        print(INSTALL_HINT, file=sys.stderr)
        return 2

    consumer = AIOKafkaConsumer(
        args.topic,
        bootstrap_servers=args.bootstrap,
        group_id=args.group,
        auto_offset_reset=args.from_beginning and "earliest" or "latest",
        enable_auto_commit=False,
        value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
    )
    await consumer.start()
    received = 0
    output = Path(args.output) if args.output else None
    try:
        async for message in consumer:
            document = message.value
            if output is not None:
                with output.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(document, ensure_ascii=False, default=str) + "\n")
            else:
                subset = {
                    key: document.get(key)
                    for key in ("event_id", "@timestamp", "data_sensitivity", "risk_score",
                                "risk_severity", "policy_decision")
                    if key in document
                }
                print(json.dumps(subset or document, ensure_ascii=False))
            received += 1
            if args.limit and received >= args.limit:
                break
        await consumer.commit()
    finally:
        await consumer.stop()
    target = str(output) if output else "консоль"
    print(f"Прочитано сообщений: {received} -> {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Публикация и чтение событий Kafka")
    subparsers = parser.add_subparsers(dest="command", required=True)

    publish_parser = subparsers.add_parser("publish", help="Отправить события из файла в топик")
    publish_parser.add_argument("--bootstrap", default="localhost:9092")
    publish_parser.add_argument("--topic", default="siem.raw.events")
    publish_parser.add_argument("--input", required=True, help="Файл событий (JSONL)")
    publish_parser.add_argument("--acks", default="all")
    publish_parser.add_argument("--rate", action="store_true", help="Небольшие паузы при отправке")
    publish_parser.set_defaults(handler=publish)

    consume_parser = subparsers.add_parser("consume", help="Прочитать обогащённые события из топика")
    consume_parser.add_argument("--bootstrap", default="localhost:9092")
    consume_parser.add_argument("--topic", default="siem.enriched.events")
    consume_parser.add_argument("--group", default="siem-enricher-inspector")
    consume_parser.add_argument("--limit", type=int, default=10)
    consume_parser.add_argument("--from-beginning", action="store_true")
    consume_parser.add_argument("--output", default=None, help="Файл для сохранения сообщений")
    consume_parser.set_defaults(handler=consume)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())

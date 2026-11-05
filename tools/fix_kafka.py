"""Правки Kafka: зависимости, явная ошибка кодека, ограничение размера документа."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
KAFKA = ROOT / "src" / "siem_enricher" / "connectors" / "kafka.py"

HELPER = '''def _slim_document(document: dict[str, Any]) -> dict[str, Any]:
    """Компактная версия документа для топика: без сырого события и тяжёлых структур."""
    slim = {key: value for key, value in document.items()
            if key not in ("raw_event", "files", "provenance_chain", "provenance_chains")}
    slim["files_count"] = len(document.get("files") or [])
    return slim


'''

SINK_INIT_OLD = '''        self.linger_ms = int(self._option("linger_ms", 20))'''
SINK_INIT_NEW = '''        self.linger_ms = int(self._option("linger_ms", 20))
        self.max_document_bytes = int(self._option("max_document_bytes", 900_000))
        self._oversize_warned = False'''

SEND_OLD = '''        try:
            await self._producer.send_and_wait(self.topic, document, key=str(document.get("event_id")).encode())'''
SEND_NEW = '''        try:
            payload = document
            size = len(json.dumps(document, ensure_ascii=False, default=str).encode("utf-8"))
            if size > self.max_document_bytes:
                payload = _slim_document(document)
                if not self._oversize_warned:
                    logger.warning(
                        "Документ урезан для Kafka: превышен предел размера",
                        extra={"topic": self.topic, "original_bytes": size,
                               "limit": self.max_document_bytes},
                    )
                    self._oversize_warned = True
            await self._producer.send_and_wait(self.topic, payload,
                                               key=str(document.get("event_id")).encode())'''

CONSUMER_OLD = '''            except Exception as exc:  # noqa: BLE001 - переживаем обрывы соединения
                logger.error("Ошибка чтения из Kafka", extra={"reason": str(exc)})'''
CONSUMER_NEW = '''            except Exception as exc:  # noqa: BLE001 - переживаем обрывы соединения
                if exc.__class__.__name__ == "UnsupportedCodecError" or "codec" in str(exc).lower():
                    logger.error(
                        "Kafka: нет кодека сжатия для топика — установите cramjam "
                        "(pip install 'siem-enricher[kafka]')",
                        extra={"topics": self.topics, "reason": str(exc)},
                    )
                    raise
                logger.error("Ошибка чтения из Kafka", extra={"reason": str(exc)})'''


def patch(path: Path, pairs: list[tuple[str, str]]) -> str:
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if new.strip() and new.strip() in text:
            print(f"  уже есть: {old[:44]}")
            continue
        if old not in text:
            print(f"  !! не найдено в {path.name}: {old[:44]}")
            continue
        text = text.replace(old, new, 1)
        print(f"  патч {path.name}: {old[:44]}")
    path.write_text(text, encoding="utf-8")
    return text


def main() -> int:
    print("pyproject:")
    patch(PYPROJECT, [('kafka = ["aiokafka>=0.10"]',
                       'kafka = ["aiokafka>=0.10", "cramjam>=2.8"]')])

    print("kafka.py:")
    text = KAFKA.read_text(encoding="utf-8")
    if "def _slim_document(" not in text:
        text = text.replace("class KafkaSource(", HELPER + "class KafkaSource(", 1)
        KAFKA.write_text(text, encoding="utf-8")
        print("  добавлена функция _slim_document")
    patch(KAFKA, [
        (SINK_INIT_OLD, SINK_INIT_NEW),
        (SEND_OLD, SEND_NEW),
        (CONSUMER_OLD, CONSUMER_NEW),
    ])

    text = KAFKA.read_text(encoding="utf-8")
    if "\nimport json\n" not in text:
        text = text.replace("from __future__ import annotations\n",
                            "from __future__ import annotations\n\nimport json\n", 1)
        KAFKA.write_text(text, encoding="utf-8")
        print("  добавлен import json")

    for path in (KAFKA, PYPROJECT):
        if path.suffix == ".py":
            ast.parse(path.read_text(encoding="utf-8"))
            print(f"  синтаксис ок: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Ускорение приёмников: Kafka без ожидания на каждое сообщение, файл с буфером."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KAFKA = ROOT / "src" / "siem_enricher" / "connectors" / "kafka.py"
BASE = ROOT / "src" / "siem_enricher" / "connectors" / "base.py"

KAFKA_OPT_OLD = '        self.linger_ms = int(self._option("linger_ms", 20))'
KAFKA_OPT_NEW = ('        self.linger_ms = int(self._option("linger_ms", 20))\n'
                 '        # False — не ждать подтверждения на каждом сообщении, а сбрасывать пачкой\n'
                 '        self.wait_ack = bool(self._option("wait_ack", True))')

KAFKA_SEND_OLD = '''            await self._producer.send_and_wait(self.topic, payload,
                                               key=str(document.get("event_id")).encode())'''
KAFKA_SEND_NEW = '''            key = str(document.get("event_id")).encode()
            if self.wait_ack:
                await self._producer.send_and_wait(self.topic, payload, key=key)
            else:
                await self._producer.send(self.topic, payload, key=key)'''

KAFKA_FLUSH_ANCHOR = "class KafkaSink(SinkConnector):"
KAFKA_FLUSH = '''class KafkaSink(SinkConnector):
    """Отправка обогащённых событий в Kafka (пакетный режим доступен через wait_ack=false)."""
'''

KAFKA_FLUSH_METHOD = '''
    async def flush(self) -> bool:
        if self._producer is None:
            return True
        try:
            await self._producer.flush()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка сброса буфера Kafka", extra={"topic": self.topic,
                                                             "reason": str(exc)})
            return False
'''

BASE_OLD = '''    async def send_many(self, documents: Sequence[dict[str, Any]]) -> int:
        """Отправить сразу несколько документов. Возвращает число успешно отправленных."""
        sent = 0
        for document in documents:
            if await self.send(document):
                sent += 1
        return sent'''
BASE_NEW = '''    async def send_many(self, documents: Sequence[dict[str, Any]]) -> int:
        """Отправить сразу несколько документов. Возвращает число успешно отправленных.

        После пачки приёмник сбрасывает буфер, поэтому режим без ожидания
        подтверждений на каждом сообщении остаётся надёжным.
        """
        sent = 0
        for document in documents:
            if await self.send(document):
                sent += 1
        await self.flush()
        return sent'''


def main() -> int:
    changed = 0
    text = KAFKA.read_text(encoding="utf-8")

    if "self.wait_ack" not in text:
        if KAFKA_OPT_OLD not in text:
            print("!! не найдена настройка linger_ms")
            return 1
        text = text.replace(KAFKA_OPT_OLD, KAFKA_OPT_NEW, 1)
        changed += 1
        print("  kafka: опция wait_ack")

    if "if self.wait_ack:" not in text:
        if KAFKA_SEND_OLD not in text:
            print("!! не найден send_and_wait")
            return 1
        text = text.replace(KAFKA_SEND_OLD, KAFKA_SEND_NEW, 1)
        changed += 1
        print("  kafka: отправка без ожидания по флагу")

    if "async def flush" not in text:
        marker = '    async def send(self, document: dict[str, Any]) -> bool:'
        index = text.index(marker)
        text = text[:index] + KAFKA_FLUSH_METHOD.lstrip("\n") + "\n" + text[index:]
        changed += 1
        print("  kafka: flush буфера")

    KAFKA.write_text(text, encoding="utf-8")
    ast.parse(text)

    base_text = BASE.read_text(encoding="utf-8")
    if "await self.flush()\n        return sent" not in base_text:
        if BASE_OLD not in base_text:
            print("  предупреждение: не найден send_many")
        else:
            base_text = base_text.replace(BASE_OLD, BASE_NEW, 1)
            BASE.write_text(base_text, encoding="utf-8")
            ast.parse(base_text)
            changed += 1
            print("  base: пачка завершается сбросом буфера")

    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

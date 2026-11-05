"""Перенос _slim_document в конец модуля: декоратор @source должен стоять у класса."""

from __future__ import annotations

import ast
from pathlib import Path

KAFKA = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "connectors" / "kafka.py"

text = KAFKA.read_text(encoding="utf-8")
start = text.find("def _slim_document(")
class_at = text.find("class KafkaSource(", start)

if start == -1:
    print("функция не найдена — возможно, уже перенесена")
elif class_at == -1:
    print("!! не найден класс KafkaSource")
else:
    block = text[start:class_at].rstrip() + "\n"
    text = text[:start] + text[class_at:]
    text = text.rstrip() + "\n\n\n" + block
    KAFKA.write_text(text, encoding="utf-8")
    print("функция перенесена в конец модуля")

ast.parse(KAFKA.read_text(encoding="utf-8"))
print("синтаксис ок")

source = KAFKA.read_text(encoding="utf-8")
print("декоратор перед классом:", "@source" in source.split("class KafkaSource(")[0][-120:])

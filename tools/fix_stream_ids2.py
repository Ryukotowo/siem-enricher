"""Уникальные id: генератор подставляет жёсткий префикс, переписываем его в потоке."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

OLD = '''        for event in chunk:
            if interval > 0:
                time.sleep(interval)
            yield event'''

NEW = '''        for position, event in enumerate(chunk, 1):
            # идентификатор содержит фиксированную метку времени, поэтому в потоке
            # делаем её уникальной для каждого повтора
            event["id"] = f"{1700000000 + attempt}.{position:06d}"
            if interval > 0:
                time.sleep(interval)
            yield event'''


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if 'event["id"] = f"{1700000000 + attempt}' in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найден цикл выдачи событий")
        return 1
    TOOL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("поток: id уникальны для каждого повтора")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

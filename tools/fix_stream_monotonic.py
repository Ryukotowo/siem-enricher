"""Поток: время событий монотонно растёт между порциями."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

OLD = '''    base = start or datetime.now(timezone.utc).replace(microsecond=0)
    attempt = 0
    while True:
        attempt += 1
        # каждый следующий повтор сдвигаем время, иначе идентификаторы совпадут
        chunk_start = base + timedelta(seconds=(attempt - 1) * max(1, count or 1))
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=chunk_start, host=host)'''

NEW = '''    base = start or datetime.now(timezone.utc).replace(microsecond=0)
    attempt = 0
    while True:
        attempt += 1
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=base, host=host)
        # следующая порция продолжает время последней, иначе события идут не по порядку
        try:
            last = max(datetime.fromisoformat(str(e["@timestamp"]).replace("Z", "+00:00"))
                       for e in chunk)
            base = last + timedelta(seconds=1)
        except (KeyError, ValueError):
            base = base + timedelta(seconds=max(1, count or 1))'''

if __name__ == "__main__":
    text = TOOL.read_text(encoding="utf-8")
    if "продолжает время последней" in text:
        print("уже исправлено")
        raise SystemExit(0)
    if OLD not in text:
        print("!! не найден блок повторов")
        raise SystemExit(1)
    TOOL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("поток: время между порциями монотонно")

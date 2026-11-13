"""Уникальные идентификаторы в потоке: сдвиг времени между повторами."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

OLD = '''    import time

    attempt = 0
    while True:
        attempt += 1
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=start, host=host)'''

NEW = '''    import time
    from datetime import timedelta

    base = start or datetime.now(timezone.utc).replace(microsecond=0)
    attempt = 0
    while True:
        attempt += 1
        # каждый следующий повтор сдвигаем время, иначе идентификаторы совпадут
        chunk_start = base + timedelta(seconds=(attempt - 1) * max(1, count or 1))
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=chunk_start, host=host)'''

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"
PANEL_OLD = "        for event in stream_events(scenario=scenario, interval=0, repeat=0):"
PANEL_NEW = ("        from datetime import UTC, datetime\n\n"
             "        started = datetime.now(tz=UTC).replace(microsecond=0)\n"
             "        for event in stream_events(scenario=scenario, interval=0, repeat=0,\n"
             "                                   start=started):")


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    if "chunk_start" in text:
        print("генератор уже исправлен")
    else:
        if OLD not in text:
            print("!! не найден блок повторов")
            return 1
        text = text.replace(OLD, NEW, 1)
        TOOL.write_text(text, encoding="utf-8")
        ast.parse(text)
        print("генератор: время сдвигается между повторами")

    panel = PANEL.read_text(encoding="utf-8")
    if "started = datetime.now(tz=UTC)" in panel:
        print("панель уже передаёт время старта")
    else:
        if PANEL_OLD not in panel:
            print("!! не найден вызов stream_events в панели")
            return 1
        panel = panel.replace(PANEL_OLD, PANEL_NEW, 1)
        PANEL.write_text(panel, encoding="utf-8")
        ast.parse(panel)
        print("панель: поток стартует от текущего времени")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

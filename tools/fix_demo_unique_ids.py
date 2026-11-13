"""Уникальные id при каждой заливке и в потоке — через общий счётчик."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

STATE_OLD = '''        state = {"running": False, "interval": 2.0, "scenario": "mixed",
                 "sent": 0, "task": None}'''
STATE_NEW = '''        state = {"running": False, "interval": 2.0, "scenario": "mixed",
                 "sent": 0, "task": None, "seq": 0}'''

HELPER_ANCHOR = "def demo_fill("
HELPER = '''def _unique_events(app: Any, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Проставить уникальные идентификаторы: генератор повторяет их от запуска к запуску."""
    state = _demo_state(app)
    state["seq"] = int(state.get("seq") or 0) + 1
    for position, event in enumerate(events, 1):
        event["id"] = f"{1700000000 + state['seq']}.{position:06d}"
    return events


def demo_fill('''

FILL_OLD = '''    events = build_events(scenario=scenario, count=max(1, min(count, 500)))'''
FILL_NEW = '''    events = _unique_events(app, build_events(scenario=scenario,
                                             count=max(1, min(count, 500))))'''

LOOP_OLD = '''        for event in stream_events(scenario=scenario, interval=0, repeat=0,
                                   start=started):
            if not state["running"]:
                break'''
LOOP_NEW = '''        batch: list[dict[str, Any]] = []
        for event in stream_events(scenario=scenario, interval=0, repeat=0,
                                   start=started):
            batch.append(event)
            if len(batch) < 10:
                continue
            _unique_events(app, batch)
            for item in batch:
                if not state["running"]:
                    return
                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None:
                    buffer.add(document)
                state["sent"] += 1
                await asyncio.sleep(max(0.1, interval))
            batch = []
        if batch:
            _unique_events(app, batch)
            for item in batch:
                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None:
                    buffer.add(document)
                state["sent"] += 1
        return

        for event in ():  # недостижимый цикл: оставлен для читаемости диффа
            if not state["running"]:
                break'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if '"seq": 0' not in text:
        text = text.replace(STATE_OLD, STATE_NEW, 1)
        changed += 1
        print("  счётчик запусков в состоянии")
    if "def _unique_events" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("  уникальные id для заливки")
    if "_unique_events(app, build_events" not in text:
        text = text.replace(FILL_OLD, FILL_NEW, 1)
        changed += 1
        print("  заливка использует уникальные id")
    if "_unique_events(app, batch)" not in text:
        text = text.replace(LOOP_OLD, LOOP_NEW, 1)
        changed += 1
        print("  поток использует уникальные id")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

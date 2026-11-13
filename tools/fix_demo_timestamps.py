"""Демо-события получают время «сейчас», а не сгенерированную дату."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

OLD = '''def _unique_events(app: Any, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Проставить уникальные идентификаторы: генератор повторяет их от запуска к запуску."""
    state = _demo_state(app)
    state["seq"] = int(state.get("seq") or 0) + 1
    for position, event in enumerate(events, 1):
        event["id"] = f"{1700000000 + state['seq']}.{position:06d}"
    return events'''

NEW = '''def _unique_events(app: Any, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Уникальные идентификаторы и текущее время: генератор повторяет и то, и другое."""
    from datetime import UTC, datetime, timedelta

    state = _demo_state(app)
    state["seq"] = int(state.get("seq") or 0) + 1
    moment = datetime.now(tz=UTC).replace(microsecond=0)
    for position, event in enumerate(events, 1):
        event["id"] = f"{1700000000 + state['seq']}.{position:06d}"
        stamp = moment + timedelta(milliseconds=position * 100)
        event["@timestamp"] = stamp.isoformat().replace("+00:00", "Z")
    return events'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "stamp = moment + timedelta" in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найдена _unique_events")
        return 1
    PANEL.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    ast.parse(NEW)
    print("демо-события получают текущее время")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

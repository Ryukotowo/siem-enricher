"""Не добавлять событие в буфер дважды: конвейер уже это делает."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

APP_OLD = '''    if register_panel(app, panel_buffer):
        pipeline.add_observer(panel_buffer.add)'''
APP_NEW = '''    if register_panel(app, panel_buffer):
        pipeline.add_observer(panel_buffer.add)
        app.state.panel_observed = True'''

PANEL_OLD = '''        _, _, document = pipeline.enrich_document("demo", event)
        if buffer is not None:
            buffer.add(document)
        sent += 1'''
PANEL_NEW = '''        _, _, document = pipeline.enrich_document("demo", event)
        if buffer is not None and not getattr(app.state, "panel_observed", False):
            buffer.add(document)
        sent += 1'''

LOOP_OLD = '''                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None:
                    buffer.add(document)
                state["sent"] += 1'''
LOOP_NEW = '''                _, _, document = pipeline.enrich_document("demo", item)
                if buffer is not None and not getattr(app.state, "panel_observed", False):
                    buffer.add(document)
                state["sent"] += 1'''

TAIL_OLD = '''            _, _, document = pipeline.enrich_document("demo", item)
            if buffer is not None:
                buffer.add(document)
            state["sent"] += 1'''
TAIL_NEW = '''            _, _, document = pipeline.enrich_document("demo", item)
            if buffer is not None and not getattr(app.state, "panel_observed", False):
                buffer.add(document)
            state["sent"] += 1'''


def main() -> int:
    changed = 0
    app_text = APP.read_text(encoding="utf-8")
    if "panel_observed" not in app_text:
        if APP_OLD not in app_text:
            print("!! не найдена регистрация наблюдателя")
            return 1
        app_text = app_text.replace(APP_OLD, APP_NEW, 1)
        APP.write_text(app_text, encoding="utf-8")
        ast.parse(app_text)
        changed += 1
        print("  app: признак наблюдателя")

    panel_text = PANEL.read_text(encoding="utf-8")
    for old, new, label in (
        (PANEL_OLD, PANEL_NEW, "заливка"),
        (LOOP_OLD, LOOP_NEW, "поток"),
        (TAIL_OLD, TAIL_NEW, "хвост потока"),
    ):
        if new in panel_text:
            continue
        if old in panel_text:
            panel_text = panel_text.replace(old, new, 1)
            changed += 1
            print(f"  {label}: без двойного добавления")
    PANEL.write_text(panel_text, encoding="utf-8")
    ast.parse(panel_text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Добавить в генератор потоковый режим и аргументы CLI."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

STREAM = '''def stream_events(
    scenario: str = "mixed",
    count: int | None = None,
    seed: int = 42,
    interval: float = 2.0,
    repeat: int = 0,
    start: datetime | None = None,
    host: str | None = None,
):
    """Отдавать события порциями с паузой — для живого потока на стенде.

    ``repeat=0`` означает бесконечный поток, ``interval`` — пауза между событиями.
    """
    import time

    attempt = 0
    while True:
        attempt += 1
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=start, host=host)
        for event in chunk:
            if interval > 0:
                time.sleep(interval)
            yield event
        if repeat and attempt >= repeat:
            return


'''

ARGS = '''    parser.add_argument("--interval", type=float, default=0.0,
                        help="пауза между событиями в секундах (0 — без пауз)")
    parser.add_argument("--repeat", type=int, default=1,
                        help="сколько раз повторить набор (0 — бесконечно)")
'''


def main() -> int:
    lines = TOOL.read_text(encoding="utf-8").splitlines()
    text = "\n".join(lines) + "\n"

    if "def stream_events" not in text:
        anchor = "def build_events("
        if anchor not in text:
            print("!! не найден build_events")
            return 1
        text = text.replace(anchor, STREAM + anchor, 1)

    if '"--interval"' not in text:
        tail = '    parser.add_argument("--stats-only", action="store_true", help="Не писать события, только сводку")\n'
        if tail not in text:
            print("!! не найден аргумент stats-only")
            return 1
        text = text.replace(tail, ARGS + tail, 1)

    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)

    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("gen", TOOL)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    items = list(module.stream_events(scenario="mixed", count=3, interval=0, repeat=2))
    print(f"проверка: {len(items)} событий в двух повторах, уникальных {len({i['event_id'] for i in items})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

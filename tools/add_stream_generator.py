"""Поток событий в реальном времени: интервал и повторения в генераторе."""

from __future__ import annotations

import ast
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

HELPER_ANCHOR = "def build_events("
HELPER = '''def stream_events(
    scenario: str = "mixed",
    count: int | None = None,
    seed: int = 42,
    interval: float = 2.0,
    repeat: int = 0,
    start: datetime | None = None,
    host: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Отдавать события порциями с паузой — для живого потока на стенде.

    ``repeat=0`` означает бесконечный поток, ``interval`` — пауза между событиями.
    """
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


def build_events('''

ARGS_ANCHOR = '    parser.add_argument("--stats-only", action="store_true", help="не писать события, только сводка")'
ARGS_NEW = '''    parser.add_argument("--interval", type=float, default=0.0,
                        help="пауза между событиями в секундах (0 — без пауз)")
    parser.add_argument("--repeat", type=int, default=1,
                        help="сколько раз повторить набор (0 — бесконечно)")
    parser.add_argument("--stats-only", action="store_true", help="не писать события, только сводка")'''

IMPORTS_OLD = "import random"
IMPORTS_NEW = "import random\nimport time\nfrom collections.abc import Iterator"


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    changed = 0
    if "def stream_events" not in text:
        if HELPER_ANCHOR not in text:
            print("!! не найден build_events")
            return 1
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("  stream_events()")
    if "from collections.abc import Iterator" not in text:
        text = text.replace(IMPORTS_OLD, IMPORTS_NEW, 1)
        changed += 1
        print("  импорты time/Iterator")
    if '"--interval"' not in text:
        if ARGS_ANCHOR not in text:
            print("!! не найдены аргументы CLI")
            return 1
        text = text.replace(ARGS_ANCHOR, ARGS_NEW, 1)
        changed += 1
        print("  аргументы --interval и --repeat")
    TOOL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

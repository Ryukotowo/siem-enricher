"""Проверка сводок: отдельная база, пути и прогресс."""

from __future__ import annotations

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "check_summaries.py"

NEW_SPEED = '''def speed(events: list[dict], use_summaries: bool) -> tuple[float, int]:
    config = load_config(ROOT / "config" / "config.local.json")
    config.ml.type = "heuristic"
    config.provenance.sqlite_path = str(Path(tempfile.mkdtemp()) / "check.db")
    pipeline = EnrichmentPipeline.from_config(config, in_memory_store=False)'''


def main() -> int:
    text = SCRIPT.read_text(encoding="utf-8")
    marker = 'def speed(events: list[dict], use_summaries: bool) -> tuple[float, int]:'
    start = text.index(marker)
    end = text.index("    pipeline = EnrichmentPipeline.from_config", start)
    end = text.index("\n", end) + 1
    block = text[start:end]
    if "tempfile.mkdtemp" in block:
        print("уже на отдельной базе")
        return 0
    text = text[:start] + NEW_SPEED + "\n" + text[end:]
    if "import tempfile" not in text:
        text = text.replace("import sys\n", "import sys\nimport tempfile\n", 1)
    SCRIPT.write_text(text, encoding="utf-8")
    print("check_summaries.py: свои временная база и импорт tempfile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

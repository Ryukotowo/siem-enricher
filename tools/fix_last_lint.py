"""Последние два замечания линтера."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "src" / "siem_enricher" / "extractor" / "metadata.py"
PATTERNS = ROOT / "src" / "siem_enricher" / "extractor" / "patterns.py"

METADATA_OLD = (
    '        elif canonical == "action_raw":\n'
    "            if meta.action is ProvenanceAction.UNKNOWN:\n"
    "                meta.action = ProvenanceAction.from_value(text)"
)
METADATA_NEW = (
    '        elif canonical == "action_raw" and meta.action is ProvenanceAction.UNKNOWN:\n'
    "            meta.action = ProvenanceAction.from_value(text)"
)

PATTERNS_OLD = (
    '    if value.startswith("/") and value.count("/") >= 1 and " " not in value:\n'
    "        return True\n"
    "    return False"
)
PATTERNS_NEW = '    return value.startswith("/") and value.count("/") >= 1 and " " not in value'


def main() -> int:
    text = METADATA.read_text(encoding="utf-8")
    if METADATA_NEW not in text:
        if METADATA_OLD not in text:
            print("!! участок в metadata.py не найден")
        else:
            METADATA.write_text(text.replace(METADATA_OLD, METADATA_NEW, 1), encoding="utf-8")
            print("metadata.py: вложенный if объединён")

    text = PATTERNS.read_text(encoding="utf-8")
    if PATTERNS_NEW not in text:
        if PATTERNS_OLD not in text:
            print("!! участок в patterns.py не найден")
        else:
            PATTERNS.write_text(text.replace(PATTERNS_OLD, PATTERNS_NEW, 1), encoding="utf-8")
            print("patterns.py: возврат условия напрямую")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Абсолютные пути в resolve_artifact_path."""

from __future__ import annotations

import ast
from pathlib import Path

CLASSIFIER = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "classifier.py"

OLD_ROOT = '    root = Path("ml") / "artifacts"'
NEW_ROOT = '    root = Path.cwd() / "ml" / "artifacts"'

OLD_RETURN = '    return newest'
NEW_RETURN = '    return newest.resolve()'


def main() -> int:
    text = CLASSIFIER.read_text(encoding="utf-8")
    changed = 0
    if OLD_ROOT in text:
        text = text.replace(OLD_ROOT, NEW_ROOT, 1)
        changed += 1
    if OLD_RETURN in text:
        text = text.replace(OLD_RETURN, NEW_RETURN, 1)
        changed += 1
    if changed:
        CLASSIFIER.write_text(text, encoding="utf-8")
        ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

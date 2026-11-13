"""Проверка целостности при выборе модели: предупреждение в журнал."""

from __future__ import annotations

import ast
from pathlib import Path

CLASSIFIER = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "classifier.py"

OLD = '''        candidate = registry.root / str(active["artifact"])
            if (candidate / "config.json").exists():
                return candidate.resolve()'''
NEW = '''        candidate = registry.root / str(active["artifact"])
            if (candidate / "config.json").exists():
                _warn_on_tampering(candidate)
                return candidate.resolve()'''

HELPER_ANCHOR = "def resolve_artifact_path("
HELPER = '''def _warn_on_tampering(directory: Path) -> None:
    """Предупредить, если файлы модели не совпадают с манифестом версии."""
    try:
        from siem_enricher.ml.registry import verify_manifest

        result = verify_manifest(directory)
        if result.get("files") and not result.get("ok"):
            logger.warning(
                "Артефакт модели не совпадает с манифестом",
                extra={"path": str(directory), "mismatched": result.get("mismatched"),
                       "missing": result.get("missing")},
            )
    except Exception:  # noqa: BLE001 - проверка не должна мешать запуску
        pass


def resolve_artifact_path('''


def main() -> int:
    text = CLASSIFIER.read_text(encoding="utf-8")
    changed = 0
    if "_warn_on_tampering" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("  проверка манифеста при выборе модели")
    if "_warn_on_tampering(candidate)" not in text:
        if OLD not in text:
            print("  предупреждение: не найден блок реестра")
        else:
            text = text.replace(OLD, NEW, 1)
            changed += 1
            print("  предупреждение о несовпадении")
    CLASSIFIER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

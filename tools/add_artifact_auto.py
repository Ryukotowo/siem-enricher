"""Пункт 2: режим ml.artifact_path = "auto" — свежий принятый артефакт."""

from __future__ import annotations

import ast
from pathlib import Path

CLASSIFIER = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "classifier.py"

HELPER_ANCHOR = "def _build_transformer("
HELPER = '''def resolve_artifact_path(path: str | Path) -> Path:
    """Выбрать артефакт модели.

    Значение ``auto`` означает «самый свежий рабочий артефакт»: каталог модели
    с ``config.json`` внутри ``ml/artifacts``, кроме отклонённых (суффикс
    ``.rejected``). Это позволяет применять принятую после дообучения модель
    без правки конфигурации.
    """
    raw = str(path).strip()
    if raw.lower() != "auto":
        return Path(raw)

    root = Path("ml") / "artifacts"
    if not root.exists():
        return Path(raw)
    candidates = [
        item for item in root.iterdir()
        if item.is_dir() and (item / "config.json").exists()
        and not item.name.endswith(".rejected")
    ]
    if not candidates:
        return Path(raw)
    newest = max(candidates, key=lambda item: (item / "config.json").stat().st_mtime)
    return newest


def _build_transformer('''

CALL_OLD = "        model_path=config.artifact_path,"
CALL_NEW = "        model_path=str(resolve_artifact_path(config.artifact_path)),"


def main() -> int:
    text = CLASSIFIER.read_text(encoding="utf-8")
    if "def resolve_artifact_path" in text:
        print("уже есть")
        return 0
    if HELPER_ANCHOR not in text:
        print("!! не найден _build_transformer")
        return 1
    text = text.replace(HELPER_ANCHOR, HELPER, 1)
    if CALL_OLD in text:
        text = text.replace(CALL_OLD, CALL_NEW, 1)
        print("model_path теперь через resolve_artifact_path")
    else:
        print("  предупреждение: не найден model_path в _build_transformer")
    CLASSIFIER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("classifier: поддержка значения auto")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

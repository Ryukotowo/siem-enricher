"""Подключение кэша классификации и настройка ml.cache_size."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "src" / "siem_enricher" / "ml" / "classifier.py"
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"

WRAPPER = '''def build_classifier(
    config: MlConfig,
    metrics: Any = None,
    labels_path: str | Path | None = None,
) -> SensitivityClassifier:
    """Создать классификатор согласно конфигурации (с кэшем по пути, если включён)."""
    classifier = _build_classifier(config, metrics=metrics, labels_path=labels_path)
    cache_size = int(getattr(config, "cache_size", 0) or 0)
    if cache_size > 0:
        from siem_enricher.ml.cache import CachingClassifier

        return CachingClassifier(classifier, max_entries=cache_size)
    return classifier


def _build_classifier('''


def patch(path: Path, pairs: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if new.split("(")[0] in text and new.strip()[:60] in text:
            print(f"  уже есть: {old[:46]}")
            continue
        if old not in text:
            print(f"  !! не найдено в {path.name}: {old[:46]}")
            continue
        text = text.replace(old, new, 1)
        print(f"  патч {path.name}: {old[:46]}")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    print("classifier.py:")
    patch(CLASSIFIER, [(
        '''def build_classifier(
    config: MlConfig,
    metrics: Any = None,
    labels_path: str | Path | None = None,
) -> SensitivityClassifier:
    """Создать классификатор согласно конфигурации."""''',
        WRAPPER.rstrip('def _build_classifier(') + 'def _build_classifier(',
    )])

    print("config.py:")
    patch(CONFIG, [
        ('        "batch_size": 16,', '        "batch_size": 16,\n        "cache_size": 4096,'),
        ("    batch_size: int = 16", "    batch_size: int = 16\n    cache_size: int = 4096"),
        ('        if self.ml.batch_size <= 0:', '        if self.ml.cache_size < 0:\n            errors.append("ml.cache_size должен быть >= 0")\n        if self.ml.batch_size <= 0:'),
    ])

    for path in (CLASSIFIER, CONFIG):
        ast.parse(path.read_text(encoding="utf-8"))
        print(f"  синтаксис ок: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

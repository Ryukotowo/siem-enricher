"""Режим auto берёт модель из реестра версий организации."""

from __future__ import annotations

import ast
from pathlib import Path

CLASSIFIER = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "classifier.py"

ANCHOR = '''    base = Path.cwd() / "ml" / "artifacts"
    if not base.exists():
        return Path(raw)'''

NEW = '''    base = Path.cwd() / "ml" / "artifacts"
    if not base.exists():
        return Path(raw)

    # реестр версий: активная версия важнее самого свежего каталога
    try:
        from siem_enricher.ml.registry import ModelRegistry

        registry = ModelRegistry(tenant or "default", base)
        active = registry.active()
        if active:
            candidate = registry.root / str(active["artifact"])
            if (candidate / "config.json").exists():
                return candidate.resolve()
        active_dir = registry.active_path()
        if (active_dir / "config.json").exists():
            return active_dir.resolve()
    except Exception:  # noqa: BLE001 - реестр не обязателен для работы
        pass
'''


def main() -> int:
    text = CLASSIFIER.read_text(encoding="utf-8")
    if "ModelRegistry" in text:
        print("уже подключено")
        return 0
    if ANCHOR not in text:
        print("!! не найден блок auto")
        return 1
    text = text.replace(ANCHOR, NEW, 1)
    CLASSIFIER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("auto: сначала реестр версий, потом свежий каталог")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

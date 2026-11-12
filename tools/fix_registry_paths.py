"""Реестр хранит относительные пути: каталог монтируется в контейнер."""

from __future__ import annotations

import ast
from pathlib import Path

REGISTRY = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "registry.py"

PAIRS = [
    ('            "artifact": str(target),',
     '            "artifact": str(target.relative_to(self.root)).replace("\\\\", "/"),'),
    ('        target = Path(target_version["artifact"])',
     '        target = self.root / str(target_version["artifact"])'),
    ('            shutil.rmtree(Path(item["artifact"]), ignore_errors=True)',
     '            shutil.rmtree(self.root / str(item["artifact"]), ignore_errors=True)'),
]


def main() -> int:
    text = REGISTRY.read_text(encoding="utf-8")
    changed = 0
    for old, new in PAIRS:
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
    if changed:
        REGISTRY.write_text(text, encoding="utf-8")
        ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

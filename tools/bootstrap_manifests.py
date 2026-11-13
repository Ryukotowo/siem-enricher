"""Разовая простановка манифестов для версий, зарегистрированных раньше."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.ml.registry import MANIFEST_NAME, ModelRegistry, build_manifest, _manifest_fingerprint  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Проставить манифесты существующим версиям")
    parser.add_argument("--tenant", default="default")
    args = parser.parse_args()

    registry = ModelRegistry(args.tenant, ROOT / "ml" / "artifacts")
    data = registry.load()
    updated = 0
    for version in data.get("versions") or []:
        directory = registry.root / str(version["artifact"])
        if not directory.exists():
            print(f"  пропуск {version['id']}: нет каталога")
            continue
        if (directory / MANIFEST_NAME).exists():
            print(f"  {version['id']}: манифест уже есть")
            continue
        manifest = build_manifest(directory)
        (directory / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        version["manifest_fingerprint"] = _manifest_fingerprint(manifest)
        updated += 1
        print(f"  {version['id']}: манифест создан, файлов {len(manifest['files'])}")

    if updated:
        registry.save(data)
    print(f"обновлено версий: {updated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

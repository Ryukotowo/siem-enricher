"""Проверка целостности артефактов модели по контрольным суммам."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.ml.registry import ModelRegistry  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка целостности артефактов модели")
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--version", default=None, help="id версии (по умолчанию активная)")
    parser.add_argument("--all", action="store_true", help="проверить все версии")
    parser.add_argument("--json", action="store_true", help="вывод в JSON")
    args = parser.parse_args()

    registry = ModelRegistry(args.tenant, ROOT / "ml" / "artifacts")

    if args.all:
        results = [registry.verify(version["id"]) for version in registry.versions()]
    else:
        results = [registry.verify(args.version)]

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        ok_count = sum(1 for item in results if item.get("ok"))
        print(f"организация: {registry.tenant}, проверено версий: {len(results)}, целых: {ok_count}")
        for item in results:
            mark = "OK  " if item.get("ok") else "БИТ"
            print(f"  {mark} {item.get('version')}  файлов {item.get('files', 0)}"
                  + ("" if item.get("ok") else f"  ({item.get('reason')}: "
                     f"{', '.join(item.get('mismatched') or item.get('missing') or [])})"))

    return 0 if all(item.get("ok") for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

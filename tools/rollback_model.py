"""Откат модели организации к предыдущей версии."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.ml.registry import ModelRegistry  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Откат модели к предыдущей версии")
    parser.add_argument("--tenant", default="default", help="организация")
    parser.add_argument("--to", default="previous", help="id версии или previous")
    parser.add_argument("--list", action="store_true", help="показать версии")
    args = parser.parse_args()

    registry = ModelRegistry(args.tenant, ROOT / "ml" / "artifacts")
    if args.list:
        data = registry.load()
        print(f"организация: {registry.tenant}, активная: {data.get('active')}")
        for version in data.get("versions") or []:
            metrics = version.get("metrics") or {}
            holdout = (metrics.get("после") or {}).get("F1")
            regression = (metrics.get("регрессия после") or {}).get("F1")
            print(f"  {version['id']:<22} {version['created']}  F1 отложенная {holdout}  регрессия {regression}")
        return 0

    try:
        version = registry.rollback(args.to, actor="cli")
    except ValueError as exc:
        print(f"откат невозможен: {exc}")
        return 1
    print(f"активная версия: {version['id']} ({version['created']})")
    print(f"рабочий каталог: {registry.active_path()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

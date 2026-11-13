"""Журнал состояния: снимки, список и откат модель+правила+конфиг."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.config import load_config  # noqa: E402
from siem_enricher.ml.state import StateJournal  # noqa: E402


def build(tenant: str | None) -> StateJournal:
    config = load_config(ROOT / "config" / "config.local.json")
    effective = tenant or config.service.tenant
    return StateJournal(
        tenant=effective,
        base=ROOT / "ml" / "artifacts",
        rules_file=ROOT / config.ml.rules_file,
        config_file=ROOT / "config" / "config.local.json",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Журнал состояния средства")
    parser.add_argument("--tenant", default=None)
    parser.add_argument("--capture", action="store_true", help="зафиксировать состояние")
    parser.add_argument("--list", action="store_true", help="показать историю")
    parser.add_argument("--rollback", default=None, help="id состояния для отката")
    parser.add_argument("--with-config", action="store_true",
                        help="при откате вернуть и файл конфигурации")
    parser.add_argument("--note", default="")
    args = parser.parse_args()

    journal = build(args.tenant)
    if args.capture:
        entry = journal.capture(actor="cli", note=args.note)
        print(json.dumps(entry, ensure_ascii=False, indent=2))
        return 0

    if args.rollback:
        try:
            result = journal.rollback(args.rollback, restore_config=args.with_config, actor="cli")
        except ValueError as exc:
            print(f"откат невозможен: {exc}")
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    entries = journal.entries()
    print(f"организация: {journal.tenant}, состояний: {len(entries)}")
    for entry in reversed(entries):
        print(f"  {entry['id']}  {entry['ts']}  модель {entry.get('model_version')}  "
              f"правила {entry.get('rules_snapshot')}  автор {entry.get('actor')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

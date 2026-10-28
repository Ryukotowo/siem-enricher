"""Быстрый прогон обогащения файла событий (обёртка над ``siem-enricher replay``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from siem_enricher import cli  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Обогатить файл событий SIEM")
    parser.add_argument("--config", default="config/config.local.json")
    parser.add_argument("--input", required=True, help="Файл событий (JSONL/JSON)")
    parser.add_argument("--output", default="var/enriched_events.jsonl")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-policies", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    forwarded = ["replay", "--config", args.config, "--input", args.input, "--output", args.output]
    if args.limit:
        forwarded += ["--limit", str(args.limit)]
    if args.no_policies:
        forwarded.append("--no-policies")
    if args.json:
        forwarded.append("--json")
    if args.quiet:
        forwarded.append("--quiet")
    return cli.main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())

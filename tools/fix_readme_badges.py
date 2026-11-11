"""Аккуратная разметка значков в README."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

CI = "https://github.com/Ryukotowo/siem-enricher/actions/workflows/ci.yml"
BADGES = [
    f"[![ci]({CI}/badge.svg)]({CI})",
    "![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)",
    "![tests](https://img.shields.io/badge/tests-140-brightgreen)",
]


def main() -> int:
    lines = README.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("# "):
        print("!! нет заголовка README")
        return 1

    rest = [line for line in lines[1:] if not (line.startswith("![") or line.startswith("[!["))]
    while rest and not rest[0].strip():
        rest.pop(0)

    result = [lines[0], ""] + BADGES + [""] + rest
    README.write_text("\n".join(result).rstrip() + "\n", encoding="utf-8")
    print("значки переписаны")
    for line in result[:6]:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

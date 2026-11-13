"""Порты в документации: 8080 -> 8081 (как публикует compose)."""

from __future__ import annotations

from pathlib import Path

REPO = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher")

FILES = ["README.md", "docs/08-развертывание.md"]


def main() -> int:
    total = 0
    for name in FILES:
        path = REPO / name
        if not path.exists():
            print(f"  нет файла {name}")
            continue
        text = path.read_text(encoding="utf-8")
        before = text
        text = text.replace("localhost:8080", "localhost:8081")
        text = text.replace("127.0.0.1:8080", "127.0.0.1:8081")
        text = text.replace("- \"8080:8080\"", "- \"8081:8080\"")
        if text != before:
            path.write_text(text, encoding="utf-8")
            replaced = sum(1 for old, new in (("8080", "8081"),) if True)
            total += before.count("8080") - text.count("8080")
            print(f"  {name}: исправлено вхождений 8080 — {before.count('8080') - text.count('8080')}")
        else:
            print(f"  {name}: менять нечего")
    print(f"всего исправлено: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

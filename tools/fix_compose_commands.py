"""Убираем кавычки в command у сервисов compose (иначе sh получает их буквально)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    # ищем блоки command: > ... " ... " и снимаем обрамляющие кавычки
    pattern = re.compile(r'(    command: >\n)((?:      .*\n)+)')

    def fix(match: re.Match[str]) -> str:
        body = match.group(2)
        if body.lstrip().startswith('"') and body.rstrip().endswith('"'):
            body = body.replace('"', "", 1)
            body = body[::-1].replace('"', "", 1)[::-1]
        return match.group(1) + body

    new_text, count = pattern.subn(fix, text)
    COMPOSE.write_text(new_text, encoding="utf-8")
    print(f"обработано блоков command: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

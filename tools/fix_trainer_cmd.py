"""Убрать CMD из образа тренера: аргументы должны попадать в обучение."""

from __future__ import annotations

from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "Dockerfile.trainer"

OLD = 'ENTRYPOINT ["trainer-entrypoint"]\nCMD ["--help"]\n'
NEW = 'ENTRYPOINT ["trainer-entrypoint"]\n'


def main() -> int:
    text = PATH.read_text(encoding="utf-8")
    if OLD not in text:
        print("CMD уже убран" if NEW in text else "!! не найдена строка CMD")
        return 0
    PATH.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    print("CMD убран: аргументы передаются в обучение")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

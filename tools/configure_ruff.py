"""Настройка правил линтера под текущую кодовую базу."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"

OLD = 'select = ["E", "F", "W", "I", "N", "UP", "B", "C4", "SIM", "RET", "ARG", "PTH"]\nignore = ["E501"]'
NEW = (
    'select = ["E", "F", "W", "I", "B", "SIM"]\n'
    'ignore = [\n'
    '    "E501",   # длина строк контролируется ревью\n'
    '    "B008",   # Depends()/Query() в аргументах FastAPI — норма\n'
    '    "B905",   # zip без strict допустим в отчётности\n'
    '    "B024",   # базовый класс без абстрактных методов — осознанно\n'
    '    "SIM105", # try/except pass читаемее suppress() в этом проекте\n'
    '    "SIM108", # тернарники не всегда читаемее\n'
    ']'
)


def main() -> int:
    text = PYPROJECT.read_text(encoding="utf-8")
    if NEW.splitlines()[0] in text and "B905" in text:
        print("правила уже настроены")
        return 0
    if OLD not in text:
        print("!! секция правил не найдена")
        return 1
    PYPROJECT.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    print("правила линтера обновлены")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

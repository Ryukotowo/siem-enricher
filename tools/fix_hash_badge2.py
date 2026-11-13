"""Значок «имя скрыто» показывается всюду, где имя не раскрывается."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

CONST_ANCHOR = 'def _clean_name(name: str | None, path: str | None) -> str:'
CONST = 'HIDDEN_NAME = "(название скрыто)"\n\n\ndef _clean_name(name: str | None, path: str | None) -> str:'

OLD_RETURN = '        return "(название скрыто)"'
NEW_RETURN = '        return HIDDEN_NAME'

OLD_RECORD = '        "hash_only": _hash_only(file_info),'
NEW_RECORD = '        "hash_only": _hash_only(file_info) or _clean_name(\n            file_info.get("name"), file_info.get("path")) == HIDDEN_NAME,'


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if "HIDDEN_NAME" not in text:
        if CONST_ANCHOR not in text:
            print("!! не найдена _clean_name")
            return 1
        text = text.replace(CONST_ANCHOR, CONST, 1)
        text = text.replace(OLD_RETURN, NEW_RETURN, 1)
        changed += 1
        print("  HIDDEN_NAME и заглушка")
    if '_clean_name(\n            file_info.get("name")' not in text:
        if OLD_RECORD not in text:
            print("  предупреждение: не найдено поле hash_only")
        else:
            text = text.replace(OLD_RECORD, NEW_RECORD, 1)
            changed += 1
            print("  значок при скрытом имени")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Исправление разбора цепочек: provenance_chains может быть списком."""

from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

TEXT = PANEL.read_text(encoding="utf-8")

OLD_CHAIN = '''    chains = document.get("provenance_chains") or {}
    raw = chains.get("steps")'''
NEW_CHAIN = '''    chains = _chains_dict(document)
    raw = chains.get("steps")'''

OLD_ENDPOINTS = '''        "endpoints": list((document.get("provenance_chains") or {}).get("external_endpoints") or [])[:6],'''
NEW_ENDPOINTS = '''        "endpoints": list(_chains_dict(document).get("external_endpoints") or [])[:6],'''

HELPER = '''def _chains_dict(document: dict[str, Any]) -> dict[str, Any]:
    """Цепочка происхождения: в документе это может быть объект или список объектов."""
    chains = document.get("provenance_chains")
    if isinstance(chains, list):
        return chains[0] if chains and isinstance(chains[0], dict) else {}
    return chains if isinstance(chains, dict) else {}


def _chain_steps('''

for old, new in ((OLD_CHAIN, NEW_CHAIN), (OLD_ENDPOINTS, NEW_ENDPOINTS)):
    if new in TEXT:
        print(f"уже есть: {old[:40]}")
    elif old in TEXT:
        TEXT = TEXT.replace(old, new, 1)
        print(f"патч: {old[:40]}")
    else:
        print(f"!! не найдено: {old[:40]}")

if "_chains_dict(document" not in TEXT:
    TEXT = TEXT.replace("def _chain_steps(", HELPER, 1)
    print("добавлена функция _chains_dict")

PANEL.write_text(TEXT, encoding="utf-8")

import ast
ast.parse(TEXT)
print("синтаксис ок")

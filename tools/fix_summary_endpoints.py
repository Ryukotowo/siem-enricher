"""Внешние адресаты в сводке считаем так же, как при обходе — по узлам."""

from __future__ import annotations

import ast
from pathlib import Path

BUILDER = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "provenance" / "builder.py"

OLD = '''        endpoints = self.summaries.externals_for(file_node_id)
        return ProvenanceChain(file_path=file_path, steps=steps, external_endpoints=endpoints)'''
NEW = '''        endpoints: list[str] = []
        for node in nodes.values():
            if node.kind in EXTERNAL_KINDS and _is_external_node(node):
                if node.label and node.label not in endpoints:
                    endpoints.append(node.label)
        return ProvenanceChain(file_path=file_path, steps=steps, external_endpoints=endpoints)'''


def main() -> int:
    text = BUILDER.read_text(encoding="utf-8")
    if NEW in text:
        print("уже так")
        return 0
    if OLD not in text:
        print("!! не найден блок endpoints в chain_from_summary")
        return 1
    text = text.replace(OLD, NEW, 1)
    BUILDER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("внешние адресаты определяются по узлам, как в обходе")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

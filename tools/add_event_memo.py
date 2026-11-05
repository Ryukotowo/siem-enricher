"""Кэш рёбер в пределах одного события + повторяемый замер."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "src" / "siem_enricher" / "provenance" / "builder.py"

INIT_OLD = "        self.max_edges_per_path = 64"
INIT_NEW = """        self.max_edges_per_path = 64
        self._edge_memo: dict[str, list[object]] = {}"""

RECORD_OLD = """        graph = self.build(event)"""
RECORD_NEW = """        self._edge_memo.clear()
        graph = self.build(event)"""

HELPER = '''    def _edges_for(self, node_ids: list[str]):
        """Рёбра инцидентные узлам: в пределах события результаты переиспользуются."""
        collected: dict[object, object] = {}
        missing: list[str] = []
        for node_id in node_ids:
            cached = self._edge_memo.get(node_id)
            if cached is None:
                missing.append(node_id)
            else:
                for edge in cached:
                    collected[id(edge)] = edge
        if missing:
            fresh = self.store.edges_touching(missing, limit=self.edge_limit)
            for edge in fresh:
                collected[id(edge)] = edge
                self._edge_memo.setdefault(edge.src, []).append(edge)
                self._edge_memo.setdefault(edge.dst, []).append(edge)
            for node_id in missing:
                self._edge_memo.setdefault(node_id, [])
        return list(collected.values())

    def chain_for('''

CHAIN_OLD = "            edges = self.store.edges_touching(sorted(frontier), limit=self.edge_limit)"
CHAIN_NEW = "            edges = self._edges_for(sorted(frontier))"


def main() -> int:
    text = BUILDER.read_text(encoding="utf-8")
    if "_edges_for" in text:
        print("уже есть")
        return 0
    for old, new, label in (
        (INIT_OLD, INIT_NEW, "поле кэша"),
        (RECORD_OLD, RECORD_NEW, "сброс на событие"),
        (CHAIN_OLD, CHAIN_NEW, "чтение из кэша"),
        ("    def chain_for(", HELPER, "метод lookups"),
    ):
        if old not in text:
            print(f"!! не найдено: {label}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {label}")
    BUILDER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

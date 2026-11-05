"""Точечная инвалидация кэша цепочек и ограничение выборки рёбер."""

from __future__ import annotations

import ast
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "provenance" / "builder.py"

RECORD_OLD = """        if graph.edges:
            self.store.add_edges(graph.edges)
            self._edge_epoch += len(graph.edges)
        return graph"""
RECORD_NEW = """        if graph.edges:
            self.store.add_edges(graph.edges)
            self._edge_epoch += len(graph.edges)
            self._invalidate_touched(event)
        return graph

    def _invalidate_touched(self, event: NormalizedEvent) -> None:
        \"\"\"Сбросить кэш только для путей, которых коснулось событие.\"\"\"
        touched = {
            str(item.path).strip().lower()
            for item in (event.files or [])
            if getattr(item, "path", None)
        }
        if not touched or not self._chain_cache:
            return
        for key in [key for key in self._chain_cache if key[0] in touched]:
            self._chain_cache.pop(key, None)"""

EDGES_OLD = "            edges = self.store.edges_touching(sorted(frontier))"
EDGES_NEW = "            edges = self.store.edges_touching(sorted(frontier), limit=self.edge_limit)"

INIT_OLD = "        self._edge_epoch = 0"
INIT_NEW = """        self._edge_epoch = 0
        self.edge_limit = 400"""


def main() -> int:
    text = FILE.read_text(encoding="utf-8")
    for old, new, label in (
        (INIT_OLD, INIT_NEW, "лимит рёбер"),
        (RECORD_OLD, RECORD_NEW, "точечная инвалидация"),
        (EDGES_OLD, EDGES_NEW, "выборка рёбер"),
    ):
        if new.strip() and new.strip() in text:
            print(f"  уже есть: {label}")
            continue
        if old not in text:
            print(f"  !! не найдено: {label}")
            return 1
        text = text.replace(old, new, 1)
        print(f"  патч: {label}")

    FILE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

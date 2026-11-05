"""Кэш цепочек происхождения по пути с инвалидацией по числу записанных рёбер."""

from __future__ import annotations

import ast
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "provenance" / "builder.py"

INIT_OLD = "        self.max_chain_depth = max_chain_depth"
INIT_NEW = """        self.max_chain_depth = max_chain_depth
        self.chain_cache_size = 4096
        self._chain_cache: OrderedDict[tuple[str, object], tuple[int, object]] = OrderedDict()
        self._edge_epoch = 0"""

RECORD_OLD = """        if graph.edges:
            self.store.add_edges(graph.edges)
        return graph"""
RECORD_NEW = """        if graph.edges:
            self.store.add_edges(graph.edges)
            self._edge_epoch += len(graph.edges)
        return graph"""

CHAIN_OLD = '''        """Восстановить цепочку происхождения файла по накопленному графу."""
        file_node_id = make_node_id(EntityKind.FILE, file_path)'''
CHAIN_NEW = '''        """Восстановить цепочку происхождения файла по накопленному графу."""
        cache_key = (str(file_path).strip().lower(), as_of)
        cached = self._chain_cache.get(cache_key)
        if cached is not None and event is None:
            epoch, chain = cached
            if epoch == self._edge_epoch:
                self._chain_cache.move_to_end(cache_key)
                return chain  # type: ignore[return-value]
            self._chain_cache.pop(cache_key, None)

        file_node_id = make_node_id(EntityKind.FILE, file_path)'''


def main() -> int:
    text = FILE.read_text(encoding="utf-8")
    if "_chain_cache" in text:
        print("кэш уже есть")
        return 0

    for old, new, label in (
        (INIT_OLD, INIT_NEW, "инициализация"),
        (RECORD_OLD, RECORD_NEW, "счётчик рёбер"),
        (CHAIN_OLD, CHAIN_NEW, "чтение кэша"),
    ):
        if old not in text:
            print(f"!! не найдено: {label}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {label}")

    if "from collections import OrderedDict" not in text:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("from dataclasses import") or line.startswith("from datetime import"):
                lines.insert(index + 1, "from collections import OrderedDict")
                break
        else:
            lines.insert(0, "from collections import OrderedDict")
        text = "\n".join(lines) + "\n"
        print("добавлен импорт OrderedDict")

    FILE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

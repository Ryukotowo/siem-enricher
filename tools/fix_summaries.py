"""Сводки: учитывать только внешние адресаты и сбрасывать при очистке графа."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "src" / "siem_enricher" / "provenance" / "builder.py"
SUMMARY = ROOT / "src" / "siem_enricher" / "provenance" / "summary.py"
TEST = ROOT / "tests" / "unit" / "test_provenance.py"

BUILDER_UPDATE_OLD = '''        for node in graph.nodes.values():
            self.summaries.add_node(node)
        for edge in graph.edges:
            self.summaries.add_edge(edge)'''
BUILDER_UPDATE_NEW = '''        for node in graph.nodes.values():
            self.summaries.add_node(node)
            if node.kind in EXTERNAL_KINDS and _is_external_node(node):
                self.summaries.add_external(node)
        for edge in graph.edges:
            self.summaries.add_edge(edge)'''

PRUNE_OLD = '''    def prune(self) -> int:
        """Удалить устаревшие рёбра графа."""
        return self.store.prune(self.ttl_seconds)'''
PRUNE_NEW = '''    def prune(self) -> int:
        """Удалить устаревшие рёбра графа и сбросить сводки компонент."""
        self.summaries.clear()
        return self.store.prune(self.ttl_seconds)'''

SUMMARY_ADD = '''    def add_external(self, node: ProvenanceNode) -> str:
        """Учесть внешний адресат: он попадёт в сводку компоненты."""
        root = self._ensure(node.id)
        self._components.setdefault(root, Component()).external[node.id] = node.label
        self._components[root].nodes.add(node.id)
        return root

    def component_for'''

SUMMARY_OLD = "    def component_for"

TEST_OLD = "        self.store.prune(ttl_seconds=0)  # очищаем граф, чтобы проверить синтетический шаг"
TEST_NEW = "        self.builder.prune()  # очищаем граф и сводки, чтобы проверить синтетический шаг"


def main() -> int:
    text = BUILDER.read_text(encoding="utf-8")
    changed = 0
    if "add_external(node)" not in text:
        if BUILDER_UPDATE_OLD not in text:
            print("!! не найден блок обновления сводок")
            return 1
        text = text.replace(BUILDER_UPDATE_OLD, BUILDER_UPDATE_NEW, 1)
        changed += 1
        print("билдер: внешние адресаты учитываются через _is_external_node")
    if "self.summaries.clear()" not in text:
        if PRUNE_OLD not in text:
            print("!! не найден метод prune")
            return 1
        text = text.replace(PRUNE_OLD, PRUNE_NEW, 1)
        changed += 1
        print("билдер: prune сбрасывает сводки")
    BUILDER.write_text(text, encoding="utf-8")
    ast.parse(text)

    summary = SUMMARY.read_text(encoding="utf-8")
    if "def add_external" not in summary:
        summary = summary.replace(SUMMARY_OLD, SUMMARY_ADD, 1)
        SUMMARY.write_text(summary, encoding="utf-8")
        ast.parse(summary)
        print("сводки: добавлен add_external")
        changed += 1

    test = TEST.read_text(encoding="utf-8")
    if TEST_OLD in test:
        TEST.write_text(test.replace(TEST_OLD, TEST_NEW, 1), encoding="utf-8")
        print("тест использует builder.prune()")
        changed += 1

    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

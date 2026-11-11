"""Точечные правки сводок: prune и внешние адресаты."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "src" / "siem_enricher" / "provenance" / "builder.py"
SUMMARY = ROOT / "src" / "siem_enricher" / "provenance" / "summary.py"
TEST = ROOT / "tests" / "unit" / "test_provenance.py"

PRUNE_OLD = "        return self.store.prune(self.ttl_seconds)"
PRUNE_NEW = ("        self.summaries.clear()\n"
             "        return self.store.prune(self.ttl_seconds)")

SUMMARY_METHOD = '''    def add_external(self, node: ProvenanceNode) -> str:
        """Учесть внешний адресат: он попадёт в сводку компоненты."""
        root = self._ensure(node.id)
        component = self._components.setdefault(root, Component())
        component.external[node.id] = node.label
        component.nodes.add(node.id)
        return root

'''


def main() -> int:
    text = BUILDER.read_text(encoding="utf-8")
    if "self.summaries.clear()" not in text:
        if PRUNE_OLD not in text:
            print("!! не найден return store.prune")
            return 1
        text = text.replace(PRUNE_OLD, PRUNE_NEW, 1)
        BUILDER.write_text(text, encoding="utf-8")
        ast.parse(text)
        print("prune сбрасывает сводки")

    summary = SUMMARY.read_text(encoding="utf-8")
    if "def add_external" not in summary:
        summary = summary.replace("    def component_for", SUMMARY_METHOD + "    def component_for", 1)
        SUMMARY.write_text(summary, encoding="utf-8")
        ast.parse(summary)
        print("сводки: добавлен add_external")

    test = TEST.read_text(encoding="utf-8")
    if "self.store.prune(ttl_seconds=0)" in test:
        test = test.replace("        self.store.prune(ttl_seconds=0)",
                            "        self.builder.prune()", 1)
        TEST.write_text(test, encoding="utf-8")
        print("тест переведён на builder.prune()")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

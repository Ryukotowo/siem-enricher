"""Подключение материализованных сводок к построителю цепочек."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "src" / "siem_enricher" / "provenance" / "builder.py"

IMPORT_OLD = "from siem_enricher.provenance.graph import"
IMPORT_NEW = "from siem_enricher.provenance.summary import ChainSummaries\nfrom siem_enricher.provenance.graph import"

INIT_OLD = "        self._edge_memo: dict[str, list[object]] = {}"
INIT_NEW = """        self._edge_memo: dict[str, list[object]] = {}
        self.summaries = ChainSummaries()
        self.use_summaries = True"""

RECORD_OLD = """            self._invalidate_touched(event)
            self._trim_history(event)"""
RECORD_NEW = """            self._invalidate_touched(event)
            self._trim_history(event)
            self._update_summaries(graph)"""

METHODS = '''    def _update_summaries(self, graph: ProvenanceGraph) -> None:
        """Материализовать новые узлы и рёбра в сводках компонент."""
        if not self.use_summaries:
            return
        for node in graph.nodes.values():
            self.summaries.add_node(node)
        for edge in graph.edges:
            self.summaries.add_edge(edge)

    def chain_from_summary(
        self,
        file_path: str,
        reference: datetime | None = None,
    ) -> ProvenanceChain | None:
        """Собрать цепочку из материализованной сводки, без обхода графа."""
        file_node_id = make_node_id(EntityKind.FILE, file_path)
        edges = self.summaries.edges_for(file_node_id)
        if not edges:
            return None

        moment = reference or utcnow()
        cutoff = moment - timedelta(seconds=self.ttl_seconds)
        fresh = [edge for edge in edges if edge.timestamp >= cutoff]
        if not fresh:
            return ProvenanceChain(file_path=file_path, steps=[], external_endpoints=[])

        node_ids = sorted({node for edge in fresh for node in (edge.src, edge.dst)})
        nodes = self.store.get_nodes(node_ids)
        steps = _dedupe_steps([self._step(edge, file_node_id, nodes, file_path) for edge in fresh])
        endpoints = self.summaries.externals_for(file_node_id)
        return ProvenanceChain(file_path=file_path, steps=steps, external_endpoints=endpoints)

    def chain_for('''

CHAIN_OLD = '''        """Восстановить цепочку происхождения файла по накопленному графу."""
        cache_key = (str(file_path).strip().lower(), as_of)'''
CHAIN_NEW = '''        """Восстановить цепочку происхождения файла по накопленному графу."""
        if self.use_summaries and as_of is None:
            reference = event.timestamp if event is not None else None
            summary_chain = self.chain_from_summary(file_path, reference)
            if summary_chain is not None and summary_chain.steps:
                return summary_chain

        cache_key = (str(file_path).strip().lower(), as_of)'''


def main() -> int:
    text = BUILDER.read_text(encoding="utf-8")
    if "chain_from_summary" in text:
        print("сводки уже подключены")
        return 0
    pairs = [
        (IMPORT_OLD, IMPORT_NEW),
        (INIT_OLD, INIT_NEW),
        (RECORD_OLD, RECORD_NEW),
        ("    def chain_for(", METHODS),
        (CHAIN_OLD, CHAIN_NEW),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:52]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:50]}")
    BUILDER.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

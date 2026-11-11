"""Тесты окна истории и настроек панели."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siem_enricher.config import ProvenanceConfig
from siem_enricher.models import FileRef, NormalizedEvent, ProvenanceAction
from siem_enricher.models.enums import EntityKind
from siem_enricher.provenance import ProvenanceBuilder, SqliteProvenanceStore
from siem_enricher.provenance.graph import ProvenanceEdge, ProvenanceNode, make_node_id


def make_event(path: str, index: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"1.{index:06d}",
        timestamp=datetime(2026, 10, 19, 10, index % 60, tzinfo=UTC),
        source="gensec",
        action=ProvenanceAction.COPY,
        host="pc-1",
        user=None,
        process=None,
        files=[FileRef(path=path, name=Path(path).name)],
    )


class HistoryWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SqliteProvenanceStore(Path(self.tmp.name) / "provenance.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)

    def test_trim_keeps_only_newest_edges(self) -> None:
        node = make_node_id(EntityKind.FILE, r"C:\data\file.docx")
        base = datetime(2026, 10, 19, 10, 0, tzinfo=UTC)
        edges = [
            ProvenanceEdge(
                src=node,
                dst=f"endpoint:{index}",
                action=ProvenanceAction.COPY,
                timestamp=base + timedelta(minutes=index),
                event_id=f"1.{index:06d}",
            )
            for index in range(10)
        ]
        self.store.add_edges(edges)
        for edge in edges:
            self.store.upsert_nodes([
                ProvenanceNode(id=edge.src, kind=EntityKind.FILE, key=edge.src,
                               label="файл", first_seen=edge.timestamp, last_seen=edge.timestamp),
                ProvenanceNode(id=edge.dst, kind=EntityKind.ENDPOINT, key=edge.dst,
                               label="адрес", first_seen=edge.timestamp, last_seen=edge.timestamp),
            ])

        removed = self.store.trim_node_edges(node, keep=3)
        self.assertEqual(removed, 7)
        remaining = self.store.edges_touching([node], limit=100)
        self.assertEqual(len(remaining), 3)

    def test_trim_with_zero_does_nothing(self) -> None:
        node = make_node_id(EntityKind.FILE, r"C:\data\file.docx")
        self.assertEqual(self.store.trim_node_edges(node, keep=0), 0)

    def test_builder_trims_history_periodically(self) -> None:
        config = ProvenanceConfig(sqlite_path=str(Path(self.tmp.name) / "p.db"), ttl_seconds=86400)
        builder = ProvenanceBuilder.from_config(config, self.store)
        builder.max_edges_per_path = 4
        builder._trim_counter = 31  # следующий вызов сработает
        for index in range(40):
            builder.record(make_event(r"C:\data\file.docx", index))
        edges = self.store.edges_touching(
            [make_node_id(EntityKind.FILE, r"C:\data\file.docx")], limit=1000
        )
        self.assertLessEqual(len(edges), 20)


class PanelSettingsTest(unittest.TestCase):
    def test_apply_rules_toggles_policy_state(self) -> None:
        from siem_enricher.service.panel import apply_rules, read_rules

        class Rule:
            def __init__(self, rule_id: str) -> None:
                self.id = rule_id
                self.title = "правило " + rule_id
                self.enabled = True

        class Engine:
            def __init__(self) -> None:
                self.rules = [Rule("POL-001"), Rule("POL-002")]

        class Pipeline:
            policy_engine = Engine()

        class State:
            runtime = None
            pipeline = Pipeline()

        class App:
            state = State()

        applied, errors = apply_rules(App(), {"POL-001": False, "POL-999": True})
        self.assertEqual(applied, ["POL-001"])
        self.assertEqual(len(errors), 1)
        states = {rule["id"]: rule["enabled"] for rule in read_rules(App())}
        self.assertFalse(states["POL-001"])
        self.assertTrue(states["POL-002"])


if __name__ == "__main__":
    unittest.main()

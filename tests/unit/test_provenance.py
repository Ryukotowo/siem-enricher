"""Тесты построения графа и цепочек происхождения."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from siem_enricher.config import ProvenanceConfig
from siem_enricher.models import (
    FileRef,
    NormalizedEvent,
    ProcessInfo,
    ProvenanceAction,
    RemoteEndpoint,
    UserInfo,
)
from siem_enricher.provenance import (
    InMemoryProvenanceStore,
    ProvenanceBuilder,
    SqliteProvenanceStore,
    build_store,
)

BASE_TIME = datetime(2025, 3, 3, 9, 0, tzinfo=UTC)
HR_FILE = r"C:\HR\Зарплатная_ведомость_2025.xlsx"
USB_FILE = r"E:\Копия_Зарплатная_ведомость_2025.xlsx"


def make_event(
    *,
    offset_minutes: int,
    action: ProvenanceAction,
    files: list[tuple[str, ProvenanceAction]],
    remote: RemoteEndpoint | None = None,
    event_id: str = "evt",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(minutes=offset_minutes),
        source="test",
        action=action,
        host="pc-hr-01",
        user=UserInfo(name="ivanov", domain="DOMAIN"),
        process=ProcessInfo(name="explorer.exe", pid=1234, path=r"C:\Windows\explorer.exe"),
        files=[FileRef(path=path, action=file_action) for path, file_action in files],
        remote=remote,
    )


class ProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryProvenanceStore()
        self.builder = ProvenanceBuilder(
            self.store, max_chain_depth=8, ttl_seconds=3600, external_actions=["upload", "send"]
        )

    def test_copy_creates_file_to_file_edge(self) -> None:
        event = make_event(
            offset_minutes=0,
            action=ProvenanceAction.COPY,
            files=[(HR_FILE, ProvenanceAction.READ), (USB_FILE, ProvenanceAction.COPY)],
            event_id="evt-copy",
        )
        self.builder.record(event)
        chain = self.builder.chain_for(USB_FILE, event)

        self.assertGreaterEqual(chain.depth, 2)
        sources = [step.counterpart_path for step in chain.steps if step.counterpart_path]
        self.assertIn(HR_FILE, sources)
        self.assertTrue(any(step.action is ProvenanceAction.COPY for step in chain.steps))

    def test_first_seen_file_gets_synthetic_step(self) -> None:
        event = make_event(
            offset_minutes=0,
            action=ProvenanceAction.READ,
            files=[(HR_FILE, ProvenanceAction.READ)],
            event_id="evt-read",
        )
        self.builder.record(event)
        self.builder.prune()  # очищаем граф, чтобы проверить синтетический шаг
        chain = self.builder.chain_for(HR_FILE, event)
        self.assertEqual(chain.depth, 1)
        self.assertIn("первое наблюдение", chain.steps[0].note)

    def test_chain_accumulates_between_events(self) -> None:
        self.builder.record(make_event(
            offset_minutes=0, action=ProvenanceAction.READ,
            files=[(HR_FILE, ProvenanceAction.READ)], event_id="evt-1",
        ))
        copy_event = make_event(
            offset_minutes=5, action=ProvenanceAction.COPY,
            files=[(HR_FILE, ProvenanceAction.READ), (USB_FILE, ProvenanceAction.COPY)],
            event_id="evt-2",
        )
        self.builder.record(copy_event)

        chain = self.builder.chain_for(HR_FILE, copy_event)
        actions = [step.action for step in chain.steps]
        self.assertIn(ProvenanceAction.READ, actions)
        self.assertIn(ProvenanceAction.COPY, actions)

    def test_external_endpoint_is_recorded(self) -> None:
        event = make_event(
            offset_minutes=0,
            action=ProvenanceAction.UPLOAD,
            files=[(HR_FILE, ProvenanceAction.READ)],
            remote=RemoteEndpoint(ip="185.220.101.5", url="https://dropbox.com/s/hr.zip",
                                  domain="dropbox.com", is_external=True, direction="outbound"),
            event_id="evt-upload",
        )
        self.builder.record(event)
        chain = self.builder.chain_for(HR_FILE, event)
        self.assertTrue(chain.external_endpoints)
        self.assertIn("dropbox.com", " ".join(chain.external_endpoints))
        self.assertTrue(any(step.direction == "outbound" for step in chain.steps))

    def test_internal_endpoint_is_not_external(self) -> None:
        event = make_event(
            offset_minutes=0,
            action=ProvenanceAction.COPY,
            files=[(HR_FILE, ProvenanceAction.READ), (USB_FILE, ProvenanceAction.COPY)],
            remote=RemoteEndpoint(ip="10.0.0.11", is_external=False),
            event_id="evt-internal",
        )
        self.builder.record(event)
        chain = self.builder.chain_for(USB_FILE, event)
        self.assertEqual(chain.external_endpoints, [])

    def test_ttl_filters_historical_edges_without_reference_event(self) -> None:
        old_event = make_event(
            offset_minutes=0, action=ProvenanceAction.READ,
            files=[(HR_FILE, ProvenanceAction.READ)], event_id="evt-old",
        )
        # Сдвигаем событие в прошлое относительно текущего момента
        old_event.timestamp = datetime.now(tz=UTC) - timedelta(days=30)
        self.builder.record(old_event)

        self.assertEqual(self.builder.chain_for(HR_FILE).depth, 0)
        self.assertGreaterEqual(self.builder.chain_for(HR_FILE, old_event).depth, 1)
        self.assertGreaterEqual(
            self.builder.chain_for(HR_FILE, as_of=old_event.timestamp).depth, 1
        )

    def test_store_stats_and_graph(self) -> None:
        self.builder.record(make_event(
            offset_minutes=0, action=ProvenanceAction.READ,
            files=[(HR_FILE, ProvenanceAction.READ)], event_id="evt-1",
        ))
        stats = self.store.stats()
        self.assertGreater(stats["nodes"], 0)
        self.assertGreater(stats["edges"], 0)

    def test_build_store_backends(self) -> None:
        self.assertIsInstance(build_store(ProvenanceConfig(backend="memory")), InMemoryProvenanceStore)
        with tempfile.TemporaryDirectory() as tmp:
            store = build_store(ProvenanceConfig(backend="sqlite", sqlite_path=str(Path(tmp) / "p.sqlite")))
            self.assertIsInstance(store, SqliteProvenanceStore)
            store.close()
        with self.assertRaises(NotImplementedError):
            build_store(ProvenanceConfig(backend="redis"))

    def test_sqlite_store_survives_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "provenance.sqlite"
            store = SqliteProvenanceStore(path)
            builder = ProvenanceBuilder(store, ttl_seconds=10 ** 9)
            event = make_event(
                offset_minutes=0, action=ProvenanceAction.COPY,
                files=[(HR_FILE, ProvenanceAction.READ), (USB_FILE, ProvenanceAction.COPY)],
                event_id="evt-copy",
            )
            builder.record(event)
            store.close()

            reopened = SqliteProvenanceStore(path)
            builder2 = ProvenanceBuilder(reopened, ttl_seconds=10 ** 9)
            chain = builder2.chain_for(USB_FILE, event)
            self.assertGreaterEqual(chain.depth, 2)
            self.assertGreater(reopened.stats()["edges"], 0)
            reopened.close()


if __name__ == "__main__":
    unittest.main()

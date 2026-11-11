"""Тесты файловых коннекторов и реестра типов."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import ConnectorConfig
from siem_enricher.connectors import available_sinks, available_sources, build_sink, build_source
from siem_enricher.connectors.file_replay import FileJsonlSink, FileReplaySource
from siem_enricher.models.enums import ProvenanceAction

EVENT_READ = {
    "@timestamp": "2025-03-03T09:00:00Z",
    "id": "1",
    "rule": {"id": "92200", "level": 6},
    "data": {"action": "read", "win": {"eventdata": {"targetFilename": r"C:\HR\Ведомость.xlsx",
                                                     "user": r"DOMAIN\ivanov"}}},
}
EVENT_UPLOAD = {
    "@timestamp": "2025-03-03T09:05:00Z",
    "id": "2",
    "data": {"action": "upload", "win": {"eventdata": {
        "targetFilename": r"C:\Users\ivanov\hr.zip", "destinationIp": "185.220.101.5"}}},
}


async def _collect(source: FileReplaySource, limit: int | None = None) -> list:
    events = []
    async for event in source.stream():
        events.append(event)
        if limit is not None and len(events) >= limit:
            break
    return events


class FileReplaySourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_jsonl(self, events: list[dict], name: str = "events.jsonl") -> Path:
        path = self.root / name
        with path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return path

    def test_jsonl_stream_normalizes_events(self) -> None:
        path = self.write_jsonl([EVENT_READ, EVENT_UPLOAD])
        source = FileReplaySource({"path": str(path)})
        events = asyncio.run(_collect(source))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].action, ProvenanceAction.READ)
        self.assertEqual(events[1].action, ProvenanceAction.UPLOAD)
        self.assertEqual(events[1].remote.ip, "185.220.101.5")
        self.assertTrue(events[1].remote.is_external)

    def test_json_array_and_wrapped_formats(self) -> None:
        array_path = self.root / "array.json"
        array_path.write_text(json.dumps([EVENT_READ, EVENT_UPLOAD]), encoding="utf-8")
        wrapped_path = self.root / "wrapped.json"
        wrapped_path.write_text(json.dumps({"events": [EVENT_READ]}), encoding="utf-8")

        self.assertEqual(len(asyncio.run(_collect(FileReplaySource({"path": str(array_path)})))), 2)
        self.assertEqual(len(asyncio.run(_collect(FileReplaySource({"path": str(wrapped_path)})))), 1)

    def test_invalid_lines_are_skipped(self) -> None:
        path = self.root / "broken.jsonl"
        path.write_text(
            json.dumps(EVENT_READ) + "\n" + "{не json}\n" + '["массив"]\n' + json.dumps(EVENT_UPLOAD) + "\n",
            encoding="utf-8",
        )
        events = asyncio.run(_collect(FileReplaySource({"path": str(path)})))
        self.assertEqual(len(events), 2)

    def test_max_events_option(self) -> None:
        path = self.write_jsonl([EVENT_READ, EVENT_UPLOAD, EVENT_READ])
        events = asyncio.run(_collect(FileReplaySource({"path": str(path), "max_events": 2})))
        self.assertEqual(len(events), 2)

    def test_missing_file_raises(self) -> None:
        source = FileReplaySource({"path": str(self.root / "absent.jsonl")})
        with self.assertRaises(FileNotFoundError):
            asyncio.run(_collect(source))

    def test_follow_mode_reads_appended_lines(self) -> None:
        path = self.root / "stream.jsonl"
        path.write_text("", encoding="utf-8")

        async def scenario() -> list:
            events: list = []
            source = FileReplaySource({"path": str(path), "follow": True, "interval_ms": 20})

            async def consume() -> None:
                async for event in source.stream():
                    events.append(event)
                    if len(events) >= 2:
                        return

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.15)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(EVENT_READ, ensure_ascii=False) + "\n")
                handle.flush()
                handle.write(json.dumps(EVENT_UPLOAD, ensure_ascii=False) + "\n")
                handle.flush()
            await asyncio.wait_for(task, timeout=10)
            return events

        events = asyncio.run(scenario())
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].action, ProvenanceAction.READ)


class SinkTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_file_sink_writes_json_lines(self) -> None:
        path = self.root / "nested" / "out.jsonl"

        async def scenario() -> bool:
            sink = FileJsonlSink({"path": str(path), "mode": "overwrite"})
            await sink.start()
            await sink.send({"event_id": "1"})
            await sink.send({"event_id": "2"})
            await sink.stop()
            return True

        asyncio.run(scenario())
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["event_id"], "1")

    def test_multi_sink_fanout(self) -> None:
        first = self.root / "first.jsonl"
        second = self.root / "second.jsonl"

        async def scenario() -> bool:
            sink = build_sink(ConnectorConfig(type="multi", options={"sinks": [
                {"type": "file_jsonl", "options": {"path": str(first)}},
                {"type": "file_jsonl", "options": {"path": str(second)}},
            ]}))
            async with sink:
                await sink.send({"event_id": "x"})
            return True

        asyncio.run(scenario())
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_webhook_sink_requires_url(self) -> None:
        with self.assertRaises(ValueError):
            build_sink(ConnectorConfig(type="webhook", options={}))

    def test_multi_sink_requires_children(self) -> None:
        with self.assertRaises(ValueError):
            build_sink(ConnectorConfig(type="multi", options={"sinks": []}))


class RegistryTest(unittest.TestCase):
    def test_known_types_are_registered(self) -> None:
        self.assertIn("kafka", available_sources())
        self.assertIn("file_replay", available_sources())
        self.assertIn("kafka", available_sinks())
        self.assertIn("file_jsonl", available_sinks())
        self.assertIn("multi", available_sinks())

    def test_unknown_source_type(self) -> None:
        with self.assertRaises(ValueError):
            build_source(ConnectorConfig(type="unknown-source", options={}))

    def test_unknown_sink_type(self) -> None:
        with self.assertRaises(ValueError):
            build_sink(ConnectorConfig(type="unknown-sink", options={}))

    def test_source_describe(self) -> None:
        source = build_source(ConnectorConfig(type="kafka", options={"topics": ["a"]}))
        info = source.describe()
        self.assertEqual(info["type"], "kafka")
        self.assertEqual(info["kind"], "source")

    def test_connector_config_is_applied(self) -> None:
        source = build_source(
            ConnectorConfig(type="file_replay", options={"path": "var/x.jsonl", "format": "json"})
        )
        self.assertEqual(str(source.path), "var\\x.jsonl" if "\\" in str(source.path) else "var/x.jsonl")
        self.assertEqual(source.format, "json")


if __name__ == "__main__":
    unittest.main()

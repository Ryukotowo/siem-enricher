"""Тесты панели: срез документа, буфер событий, подписка на поток."""

from __future__ import annotations

import unittest

from siem_enricher.service.panel import EventBuffer, compact


def document(**overrides):
    base = {
        "event_id": "1.000001",
        "@timestamp": "2026-10-19T10:08:09Z",
        "action": "copy",
        "file": {"name": "отчёт.docx", "path": r"C:\Проекты\отчёт.docx", "directory": r"C:\Проекты"},
        "data_sensitivity": "confidential",
        "data_sensitivity_ru": "Конфиденциальная",
        "sensitivity_confidence": 0.83,
        "sensitivity_method": "hybrid",
        "sensitivity_reason": "правило размещения",
        "risk_score": 0.62,
        "risk_severity": "high",
        "policy_decision": "block",
        "policy_rule_ids": ["POL-012"],
        "provenance_depth": 4,
        "external_destinations_count": 1,
        "removable_destinations_count": 0,
        "risk_components": {"sensitivity": 0.4},
    }
    base.update(overrides)
    return base


class CompactTest(unittest.TestCase):
    def test_keeps_required_fields(self) -> None:
        record = compact(document())
        self.assertEqual(record["event_id"], "1.000001")
        self.assertEqual(record["file"], "отчёт.docx")
        self.assertEqual(record["sensitivity"], "confidential")
        self.assertEqual(record["decision"], "block")
        self.assertEqual(record["rules"], ["POL-012"])
        self.assertAlmostEqual(record["risk"], 0.62)

    def test_hash_only_file_is_marked(self) -> None:
        hashed = "sha256:310060f5bcc80e07"
        record = compact(document(file={"name": hashed, "path": hashed, "hash": hashed}))
        self.assertTrue(record["hash_only"])
        self.assertEqual(record["file"], "(файл по хэшу)")

    def test_name_is_taken_from_path_when_missing(self) -> None:
        record = compact(document(file={"name": "", "path": r"C:\HR\ведомость.xlsx"}))
        self.assertEqual(record["file"], "ведомость.xlsx")
        self.assertFalse(record["hash_only"])

    def test_missing_fields_do_not_break(self) -> None:
        record = compact({"event_id": "2"})
        self.assertEqual(record["event_id"], "2")
        self.assertIsNone(record["sensitivity"])
        self.assertEqual(record["rules"], [])


class EventBufferTest(unittest.TestCase):
    def test_recent_returns_newest_first(self) -> None:
        buffer = EventBuffer(10)
        buffer.add(document(event_id="1"))
        buffer.add(document(event_id="2"))
        self.assertEqual([item["event_id"] for item in buffer.recent(2)], ["2", "1"])

    def test_duplicate_event_replaces_previous(self) -> None:
        buffer = EventBuffer(10)
        buffer.add(document(event_id="1", risk_score=0.1))
        buffer.add(document(event_id="1", risk_score=0.9))
        items = buffer.recent(10)
        self.assertEqual(len(items), 1)
        self.assertAlmostEqual(items[0]["risk"], 0.9)

    def test_size_limit_is_respected(self) -> None:
        buffer = EventBuffer(2)
        for index in range(5):
            buffer.add(document(event_id=str(index)))
        self.assertEqual(len(buffer.recent(10)), 2)

    def test_stats_counts_critical_and_blocked(self) -> None:
        buffer = EventBuffer(10)
        buffer.add(document(event_id="1", risk_severity="critical", policy_decision="block"))
        buffer.add(document(event_id="2", risk_severity="low", policy_decision="allow"))
        stats = buffer.stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["critical"], 1)
        self.assertEqual(stats["blocked"], 1)

    def test_subscriber_receives_events(self) -> None:
        buffer = EventBuffer(10)
        received = []
        buffer.subscribe(received.append)
        buffer.add(document(event_id="7"))
        self.assertEqual([item["event_id"] for item in received], ["7"])

    def test_broken_subscriber_is_dropped(self) -> None:
        buffer = EventBuffer(10)

        def failing(_record):
            raise RuntimeError("подписчик недоступен")

        buffer.subscribe(failing)
        buffer.add(document(event_id="1"))
        buffer.add(document(event_id="2"))
        self.assertEqual(len(buffer.recent(10)), 2)


if __name__ == "__main__":
    unittest.main()

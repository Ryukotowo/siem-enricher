"""Тесты меток аналитика."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import read_labels, save_label


class App:
    class State:
        audit_actor = "ivanov"

    state = State()


class AnalystLabelsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._original = panel_module.LABELS_FILE
        panel_module.LABELS_FILE = str(Path(self.tmp.name) / "labels.jsonl")
        self.addCleanup(setattr, panel_module, "LABELS_FILE", self._original)

    def path(self) -> Path:
        return Path(panel_module.LABELS_FILE)

    def test_label_is_saved_with_actor(self) -> None:
        record, errors = save_label(App(), {
            "event_id": "1.000001", "label": "confirmed", "comment": "проверил",
            "file": "отчёт.docx", "decision": "block", "risk": 0.9,
        })
        self.assertEqual(errors, [])
        self.assertEqual(record["label"], "confirmed")
        self.assertEqual(record["actor"], "ivanov")
        self.assertEqual(record["comment"], "проверил")
        lines = self.path().read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["event_id"], "1.000001")

    def test_unknown_label_is_rejected(self) -> None:
        record, errors = save_label(App(), {"event_id": "1", "label": "может быть"})
        self.assertIsNone(record)
        self.assertTrue(errors)
        self.assertFalse(self.path().exists())

    def test_empty_event_id_is_rejected(self) -> None:
        _, errors = save_label(App(), {"event_id": "", "label": "confirmed"})
        self.assertTrue(errors)

    def test_counts_use_latest_label_per_event(self) -> None:
        save_label(App(), {"event_id": "1", "label": "confirmed"})
        save_label(App(), {"event_id": "2", "label": "false_positive"})
        save_label(App(), {"event_id": "1", "label": "false_positive"})
        data = read_labels(App(), limit=10)
        self.assertEqual(data["counts"], {"confirmed": 0, "false_positive": 2})
        self.assertEqual(len(data["records"]), 3)
        self.assertEqual(data["records"][0]["event_id"], "1")


if __name__ == "__main__":
    unittest.main()

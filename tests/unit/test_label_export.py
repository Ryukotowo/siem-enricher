"""Тесты экспорта датасета из меток аналитиков."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import export_training_rows, save_label


class App:
    class State:
        audit_actor = "tester"

    state = State()


class LabelExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._original = panel_module.LABELS_FILE
        panel_module.LABELS_FILE = str(Path(self.tmp.name) / "labels.jsonl")
        self.addCleanup(setattr, panel_module, "LABELS_FILE", self._original)

    def label(self, **kwargs) -> None:
        payload = {"event_id": "1.1", "label": "confirmed", **kwargs}
        record, errors = save_label(App(), payload)
        self.assertEqual(errors, [], payload)
        self.assertIsNotNone(record)

    def test_confirmed_uses_predicted_level(self) -> None:
        self.label(path=r"C:\HR\ведомость.xlsx", level="confidential", file="ведомость.xlsx")
        rows = export_training_rows(App())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["level"], "confidential")
        self.assertEqual(rows[0]["path"], r"C:\HR\ведомость.xlsx")

    def test_true_level_overrides_prediction(self) -> None:
        self.label(path=r"C:\Public\пресс-релиз.docx", level="confidential",
                   true_level="public", label="false_positive")
        rows = export_training_rows(App())
        self.assertEqual(rows[0]["level"], "public")

    def test_rows_without_path_are_skipped(self) -> None:
        self.label(event_id="1.2", level="secret")
        self.assertEqual(export_training_rows(App()), [])

    def test_duplicate_path_keeps_last_label(self) -> None:
        self.label(event_id="1.3", path=r"C:\data\file.docx", level="internal")
        self.label(event_id="1.4", path=r"C:\data\file.docx", level="confidential")
        rows = export_training_rows(App())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["level"], "confidential")
        self.assertEqual(rows[0]["event_id"], "1.4")

    def test_invalid_true_level_is_rejected(self) -> None:
        record, errors = save_label(App(), {
            "event_id": "1.5", "label": "confirmed", "path": r"C:\a.docx",
            "true_level": "совершенно секретно",
        })
        self.assertIsNone(record)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()

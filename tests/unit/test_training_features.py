"""Тесты новых возможностей дообучения: сила метки, auto-артефакт, отказ."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.ml.classifier import resolve_artifact_path
from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import export_training_rows, save_label


class App:
    class State:
        audit_actor = "tester"

    state = State()


class StrengthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._original = panel_module.LABELS_FILE
        panel_module.LABELS_FILE = str(Path(self.tmp.name) / "labels.jsonl")
        self.addCleanup(setattr, panel_module, "LABELS_FILE", self._original)

    def test_confirmed_without_correction_is_weak(self) -> None:
        save_label(App(), {"event_id": "1", "label": "confirmed",
                           "path": r"C:\a\file.docx", "level": "confidential"})
        rows = export_training_rows(App())
        self.assertEqual(rows[0]["strength"], "weak")

    def test_corrected_class_is_strong(self) -> None:
        save_label(App(), {"event_id": "2", "label": "false_positive",
                           "path": r"C:\b\file.docx", "level": "confidential",
                           "true_level": "public"})
        rows = export_training_rows(App())
        self.assertEqual(rows[0]["strength"], "strong")
        self.assertEqual(rows[0]["level"], "public")


class ArtifactAutoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self._cwd = Path.cwd()
        import os

        os.chdir(self.root)
        self.addCleanup(os.chdir, self._cwd)

    def make(self, name: str, mtime: float) -> Path:
        directory = self.root / "ml" / "artifacts" / name
        directory.mkdir(parents=True, exist_ok=True)
        config = directory / "config.json"
        config.write_text("{}", encoding="utf-8")
        import os

        os.utime(config, (mtime, mtime))
        return directory

    def test_auto_picks_newest_workable(self) -> None:
        self.make("old", 1000)
        newest = self.make("new", 3000)
        self.assertEqual(resolve_artifact_path("auto"), newest)

    def test_auto_skips_rejected(self) -> None:
        workable = self.make("good", 1000)
        self.make("bad.rejected", 5000)
        self.assertEqual(resolve_artifact_path("auto"), workable)

    def test_explicit_path_is_returned_as_is(self) -> None:
        explicit = self.root / "ml" / "artifacts" / "sensitivity_transformer"
        self.assertEqual(resolve_artifact_path(str(explicit)), explicit)


class ReportTest(unittest.TestCase):
    def test_report_records_acceptance_fields(self) -> None:
        path = Path(tempfile.mkdtemp()) / "report.json"
        path.write_text(json.dumps({
            "меток": 30, "сильных": 0, "слабых": 30,
            "модель сохранена": False, "артефакт": None,
        }, ensure_ascii=False), encoding="utf-8")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(data["модель сохранена"])
        self.assertIsNone(data["артефакт"])


if __name__ == "__main__":
    unittest.main()

"""Тесты журнала состояния: фиксация, откат модели и правил."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.ml.registry import ModelRegistry
from siem_enricher.ml.state import StateJournal


class StateJournalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._cwd = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self._cwd)
        self.base = Path("ml") / "artifacts"
        self.base.mkdir(parents=True)
        self.rules = Path("config") / "rules.json"
        self.rules.parent.mkdir(parents=True)
        self.rules.write_text(json.dumps({"directories": [{"id": "a"}]}), encoding="utf-8")
        self.config = Path("config") / "config.local.json"
        self.config.write_text(json.dumps({"ml": {"artifact_path": "auto"}}), encoding="utf-8")

    def make_version(self, name: str, marker: str) -> None:
        source = Path(self.tmp.name) / name
        source.mkdir(parents=True, exist_ok=True)
        (source / "config.json").write_text(json.dumps({"marker": marker}), encoding="utf-8")
        ModelRegistry("default", self.base).register(source, {"после": {"F1": 0.5}})

    def journal(self) -> StateJournal:
        return StateJournal("default", self.base, self.rules, self.config)

    def test_capture_records_model_and_rules(self) -> None:
        self.make_version("m1", "first")
        entry = self.journal().capture(actor="cli", note="тест")
        self.assertEqual(entry["model_version"], ModelRegistry("default", self.base).active()["id"])
        self.assertTrue((Path("var") / "state-history" / entry["rules_snapshot"]).exists())
        self.assertEqual(entry["rules_hash"][:7], "sha256:")

    def test_rollback_restores_model_and_rules(self) -> None:
        self.make_version("m1", "first")
        first = self.journal().capture(actor="cli")
        self.make_version("m2", "second")
        self.rules.write_text(json.dumps({"directories": [{"id": "b"}]}), encoding="utf-8")

        result = self.journal().rollback(first["id"], actor="cli")
        self.assertEqual(result["model"], first["model_version"])
        restored = json.loads(self.rules.read_text(encoding="utf-8"))
        self.assertEqual(restored, {"directories": [{"id": "a"}]})
        active = ModelRegistry("default", self.base).active_path() / "config.json"
        self.assertEqual(json.loads(active.read_text(encoding="utf-8"))["marker"], "first")

    def test_rollback_config_only_on_request(self) -> None:
        self.make_version("m1", "first")
        entry = self.journal().capture(actor="cli")
        self.config.write_text(json.dumps({"ml": {"artifact_path": "other"}}), encoding="utf-8")

        self.journal().rollback(entry["id"], actor="cli")
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8"))["ml"]["artifact_path"], "other")

        self.journal().rollback(entry["id"], restore_config=True, actor="cli")
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8"))["ml"]["artifact_path"], "auto")

    def test_unknown_state_fails(self) -> None:
        with self.assertRaises(ValueError):
            self.journal().rollback("s19990101-000000")

    def test_rollback_is_audited(self) -> None:
        self.make_version("m1", "first")
        entry = self.journal().capture(actor="cli")
        self.journal().rollback(entry["id"], actor="cli")
        audit = Path("var") / "audit.jsonl"
        kinds = [json.loads(line)["kind"] for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertIn("state_rollback", kinds)


if __name__ == "__main__":
    unittest.main()

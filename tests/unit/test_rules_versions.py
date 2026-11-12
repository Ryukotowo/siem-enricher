"""Тесты версий правил и перезагрузки модели."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import rollback_rules, rules_versions, snapshot_rules


class Config:
    class Ml:
        rules_file = ""

    def __init__(self, rules_file: str) -> None:
        self.ml = Config.Ml()
        self.ml.rules_file = rules_file


class RulesVersionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._cwd = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self._cwd)
        self.rules = Path(self.tmp.name) / "config" / "rules.json"
        self.rules.parent.mkdir(parents=True)
        self.rules.write_text(json.dumps({"directories": []}), encoding="utf-8")
        self._original = panel_module.RULES_HISTORY_DIR
        panel_module.RULES_HISTORY_DIR = "var/rules-history"
        self.addCleanup(setattr, panel_module, "RULES_HISTORY_DIR", self._original)

    def test_snapshot_creates_history_entry(self) -> None:
        name = snapshot_rules(Config(str(self.rules)))
        self.assertIsNotNone(name)
        self.assertTrue((Path("var/rules-history") / name).exists())

    def test_versions_listed_newest_first(self) -> None:
        import time

        snapshot_rules(Config(str(self.rules)))
        time.sleep(1.1)
        self.rules.write_text(json.dumps({"directories": [{"id": "x"}]}), encoding="utf-8")
        snapshot_rules(Config(str(self.rules)))
        versions = rules_versions()
        self.assertEqual(len(versions), 2)
        self.assertGreater(versions[0]["name"], versions[1]["name"])

    def test_rollback_restores_file(self) -> None:
        snapshot_rules(Config(str(self.rules)))
        name = rules_versions()[0]["name"]
        self.rules.write_text(json.dumps({"directories": [{"id": "new"}]}), encoding="utf-8")
        result = rollback_rules(Config(str(self.rules)), name)
        self.assertTrue(result["ok"])
        restored = json.loads(self.rules.read_text(encoding="utf-8"))
        self.assertEqual(restored, {"directories": []})

    def test_rollback_unknown_version_fails(self) -> None:
        result = rollback_rules(Config(str(self.rules)), "rules-19700101-000000.json")
        self.assertFalse(result["ok"])

    def test_history_is_limited(self) -> None:
        original = panel_module.RULES_KEEP
        panel_module.RULES_KEEP = 2
        self.addCleanup(setattr, panel_module, "RULES_KEEP", original)
        import time

        for index in range(4):
            self.rules.write_text(json.dumps({"directories": [{"id": str(index)}]}), encoding="utf-8")
            snapshot_rules(Config(str(self.rules)))
            time.sleep(1.1)
        self.assertLessEqual(len(rules_versions()), 2)


if __name__ == "__main__":
    unittest.main()

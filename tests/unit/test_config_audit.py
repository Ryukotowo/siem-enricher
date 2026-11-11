"""Тесты аудита изменений конфигурации."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import apply_rules, apply_settings, read_audit_tail


class Rule:
    def __init__(self, rule_id: str) -> None:
        self.id = rule_id
        self.title = "правило " + rule_id
        self.enabled = True


class Engine:
    def __init__(self) -> None:
        self.rules = [Rule("POL-001"), Rule("POL-008")]
        self.mode = "dry_run"
        self.stop_on_block = True


class Classifier:
    def __init__(self) -> None:
        self.max_entries = 4096


class Scorer:
    def __init__(self) -> None:
        self.thresholds = {"medium": 0.3, "high": 0.6, "critical": 0.85}


class Pipeline:
    def __init__(self) -> None:
        self.policy_engine = Engine()
        self.classifier = Classifier()
        self.scorer = Scorer()
        self.max_edges_per_path = 64
        self.edge_limit = 120


class Config:
    def __init__(self, path: Path) -> None:
        self.audit_log_path = path


class State:
    def __init__(self, path: Path) -> None:
        self.pipeline = Pipeline()
        self.config = Config(path)
        self.runtime = None


class App:
    def __init__(self, path: Path) -> None:
        self.state = State(path)


class ConfigAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "audit.jsonl"
        self.app = App(self.path)
        self._original_settings_file = panel_module.SETTINGS_FILE
        panel_module.SETTINGS_FILE = str(Path(self.tmp.name) / "runtime-settings.json")
        self.addCleanup(setattr, panel_module, "SETTINGS_FILE", self._original_settings_file)

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def test_threshold_change_is_audited(self) -> None:
        self.app.state.audit_actor = "ivanov"
        apply_settings(self.app, {"risk.high": 0.45})
        entries = [item for item in self.records() if item.get("key") == "risk.high"]
        self.assertTrue(entries)
        entry = entries[-1]
        self.assertEqual(entry["kind"], "config_change")
        self.assertEqual(entry["actor"], "ivanov")
        self.assertEqual(entry["from"], 0.6)
        self.assertEqual(entry["to"], 0.45)

    def test_rule_toggle_is_audited(self) -> None:
        apply_rules(self.app, {"POL-008": False})
        entries = [item for item in self.records() if item.get("rule") == "POL-008"]
        self.assertTrue(entries)
        self.assertFalse(entries[-1]["to"])
        self.assertTrue(entries[-1]["from"])

    def test_unchanged_value_is_not_audited(self) -> None:
        apply_settings(self.app, {"risk.high": 0.6})
        entries = [item for item in self.records() if item.get("key") == "risk.high"]
        self.assertFalse(entries)

    def test_tail_returns_newest_first(self) -> None:
        apply_settings(self.app, {"risk.high": 0.45})
        apply_settings(self.app, {"risk.high": 0.5})
        tail = read_audit_tail(self.app, limit=10)
        self.assertGreaterEqual(len(tail), 2)
        self.assertEqual(tail[0]["to"], 0.5)


if __name__ == "__main__":
    unittest.main()

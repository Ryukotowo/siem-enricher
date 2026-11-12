"""Тесты правил из конфигурации."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.ml.rules_config import load_rules


class RulesConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "rules.json"

    def write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def test_new_directory_rule_is_added(self) -> None:
        self.write({"directories": [{
            "id": "dir_sales", "level": "confidential", "weight": 1.2,
            "pattern": r"(?i)(\\|/)(отдел продаж|sales)(\\|/)", "note": "коммерция",
        }]})
        spec = load_rules(self.path)
        names = [rule.name for rule in spec.directory_rules]
        self.assertIn("dir_sales", names)
        self.assertEqual(spec.errors, [])

    def test_existing_rule_is_overridden(self) -> None:
        self.write({"directories": [{
            "id": "dir_public", "level": "internal", "weight": 0.5,
            "pattern": r"(?i)(\\|/)(public|общие)(\\|/)", "note": "переопределено",
        }]})
        spec = load_rules(self.path)
        rule = next(item for item in spec.directory_rules if item.name == "dir_public")
        self.assertEqual(rule.level.value, "internal")
        self.assertAlmostEqual(rule.weight, 0.5)

    def test_rule_can_be_disabled(self) -> None:
        self.write({"directories": [{"id": "dir_public", "enabled": False}]})
        spec = load_rules(self.path)
        self.assertNotIn("dir_public", [rule.name for rule in spec.directory_rules])

    def test_extension_rule_is_replaced(self) -> None:
        self.write({"extensions": {".1c": {"level": "internal", "weight": 0.9}}})
        spec = load_rules(self.path)
        self.assertIn(".1c", spec.extension_rules)
        self.assertEqual(spec.extension_rules[".1c"][0].value, "internal")

    def test_invalid_pattern_is_reported_not_raised(self) -> None:
        self.write({"filenames": [{"id": "bad", "pattern": "(unclosed", "level": "secret"}]})
        spec = load_rules(self.path)
        self.assertTrue(spec.errors)
        self.assertNotIn("bad", [rule.name for rule in spec.filename_rules])

    def test_missing_file_keeps_defaults(self) -> None:
        spec = load_rules(Path(self.tmp.name) / "none.json")
        self.assertTrue(spec.directory_rules)
        self.assertEqual(spec.errors, None)


if __name__ == "__main__":
    unittest.main()

"""Интеграционные тесты командного интерфейса."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests import PROJECT_ROOT
from tests.integration.test_pipeline_end_to_end import build_config_dict

from siem_enricher import cli
from tools.generate_sample_events import build_events


class CommandLineTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(
            json.dumps(build_config_dict(self.root), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_events(self, count: int | None = None, scenario: str = "mixed") -> Path:
        path = self.root / "events.jsonl"
        events = build_events(scenario=scenario, count=count, seed=11)
        with path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return path

    def test_version_and_connectors(self) -> None:
        self.assertEqual(cli.main(["version"]), 0)
        self.assertEqual(cli.main(["connectors"]), 0)

    def test_validate_config(self) -> None:
        self.assertEqual(cli.main(["validate-config", "--config", str(self.config_path)]), 0)

    def test_validate_config_reports_broken_rules(self) -> None:
        broken = json.loads(self.config_path.read_text(encoding="utf-8"))
        rules_path = self.root / "broken_policies.json"
        rules_path.write_text(json.dumps({"rules": [{"id": "X", "when": {"all": []}, "then": []}]}),
                              encoding="utf-8")
        broken["policy"]["file"] = str(rules_path)
        broken_path = self.root / "broken_config.json"
        broken_path.write_text(json.dumps(broken, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(cli.main(["validate-config", "--config", str(broken_path)]), 1)

    def test_classify_command(self) -> None:
        code = cli.main([
            "classify", "--config", str(self.config_path),
            "--path", r"C:\keys\id_rsa", "--path", r"C:\Public\readme.md", "--json",
        ])
        self.assertEqual(code, 0)

    def test_replay_command_writes_enriched_events(self) -> None:
        input_path = self.write_events()
        output_path = self.root / "enriched.jsonl"
        code = cli.main([
            "replay", "--config", str(self.config_path),
            "--input", str(input_path), "--output", str(output_path), "--json", "--quiet",
        ])
        self.assertEqual(code, 0)
        lines = output_path.read_text(encoding="utf-8").strip().splitlines()
        expected = len(input_path.read_text(encoding="utf-8").strip().splitlines())
        self.assertEqual(len(lines), expected)

        first = json.loads(lines[0])
        self.assertIn("data_sensitivity", first)
        self.assertIn("provenance_chain", first)
        self.assertIn("risk_score", first)

    def test_replay_command_honours_limit(self) -> None:
        input_path = self.write_events()
        output_path = self.root / "limited.jsonl"
        code = cli.main([
            "replay", "--config", str(self.config_path),
            "--input", str(input_path), "--output", str(output_path), "--limit", "3", "--json", "--quiet",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(len(output_path.read_text(encoding="utf-8").strip().splitlines()), 3)

    def test_chain_command(self) -> None:
        input_path = self.write_events()
        output_path = self.root / "enriched.jsonl"
        cli.main([
            "replay", "--config", str(self.config_path),
            "--input", str(input_path), "--output", str(output_path), "--json", "--quiet",
        ])
        # Цепочка сохраняется в SQLite только при backend=sqlite; в тестовой конфигурации память,
        # поэтому команда должна корректно отработать с пустым графом
        code = cli.main(["chain", "--config", str(self.config_path),
                         "--path", r"C:\HR\Зарплатная_ведомость_2025.xlsx", "--json"])
        self.assertEqual(code, 0)

    def test_unknown_command_fails(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["unknown-command"])

    def test_default_config_paths_exist(self) -> None:
        for name in ("config.example.json", "config.local.json", "config.docker.json", "policies.json",
                     "sensitivity_labels.json"):
            with self.subTest(name=name):
                self.assertTrue((PROJECT_ROOT / "config" / name).exists())


if __name__ == "__main__":
    unittest.main()

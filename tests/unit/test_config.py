"""Тесты загрузки и проверки конфигурации."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import AppConfig, ConfigError, expand_env, load_config, load_structured

BASE_CONFIG = {
    "service": {"instance_id": "${TEST_INSTANCE:-local-test}"},
    "source": {"type": "kafka", "options": {"bootstrap_servers": "${TEST_BOOTSTRAP:-localhost:9092}"}},
    "sink": {"type": "file_jsonl", "options": {"path": "var/out.jsonl"}},
    "ml": {"type": "heuristic", "artifact_path": "ml/artifacts/sensitivity_transformer"},
    "provenance": {"backend": "memory"},
    "policy": {"file": "config/policies.json", "mode": "dry_run"},
}


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "config").mkdir(parents=True, exist_ok=True)
        self.path = self.root / "config" / "config.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, payload: dict) -> Path:
        self.path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return self.path

    def test_env_substitution_with_defaults(self) -> None:
        self.write(BASE_CONFIG)
        config = load_config(self.path, environ={})
        self.assertEqual(config.service.instance_id, "local-test")
        self.assertEqual(config.source.options["bootstrap_servers"], "localhost:9092")

        config = load_config(
            self.path,
            environ={"TEST_INSTANCE": "enricher-7", "TEST_BOOTSTRAP": "kafka:9092"},
        )
        self.assertEqual(config.service.instance_id, "enricher-7")
        self.assertEqual(config.source.options["bootstrap_servers"], "kafka:9092")

    def test_missing_env_without_default_raises(self) -> None:
        payload = dict(BASE_CONFIG)
        payload["service"] = {"instance_id": "${REQUIRED_VAR}"}
        self.write(payload)
        with self.assertRaises(ConfigError):
            load_config(self.path, environ={})

    def test_expand_env_is_recursive(self) -> None:
        result = expand_env({"a": ["${X:-1}", {"b": "${X:-1}"}]}, environ={})
        self.assertEqual(result, {"a": ["1", {"b": "1"}]})

    def test_defaults_are_filled(self) -> None:
        self.write({"source": {"type": "kafka"}})
        config = load_config(self.path)
        self.assertEqual(config.sink.type, "file_jsonl")
        self.assertEqual(config.risk.thresholds["critical"], 0.85)
        self.assertEqual(config.runtime.shutdown_grace_seconds, 15)
        self.assertTrue(config.ml.hybrid_enabled)
        self.assertEqual(config.ml.type, "auto")

    def test_base_dir_detected_from_config_directory(self) -> None:
        self.write(BASE_CONFIG)
        config = load_config(self.path)
        self.assertEqual(config.base_dir, self.root)
        self.assertEqual(config.resolve("var/out.jsonl"), self.root / "var" / "out.jsonl")

    def test_validation_reports_problems(self) -> None:
        payload = json.loads(json.dumps(BASE_CONFIG))
        payload["ml"]["type"] = "magic"
        payload["risk"] = {"thresholds": {"medium": 0.9, "high": 0.6, "critical": 0.85}}
        payload["provenance"]["backend"] = "filesystem"
        payload["policy"]["mode"] = "unknown"
        payload["ml"]["device"] = "tpu"
        self.write(payload)
        config = AppConfig.from_dict(json.loads(self.path.read_text(encoding="utf-8")))
        errors = config.validate()
        joined = " ".join(errors)
        self.assertIn("ml.type", joined)
        self.assertIn("risk.thresholds", joined)
        self.assertIn("provenance.backend", joined)
        self.assertIn("policy.mode", joined)
        self.assertIn("ml.device", joined)

    def test_live_policy_mode_forbidden_in_dev(self) -> None:
        payload = json.loads(json.dumps(BASE_CONFIG))
        payload["service"]["environment"] = "dev"
        payload["policy"]["mode"] = "live"
        self.write(payload)
        config = AppConfig.from_dict(payload)
        self.assertTrue(any("live" in error for error in config.validate()))

    def test_hybrid_thresholds_validated(self) -> None:
        payload = json.loads(json.dumps(BASE_CONFIG))
        payload["ml"]["hybrid_downgrade_max_model_confidence"] = 1.5
        config = AppConfig.from_dict(payload)
        self.assertTrue(any("hybrid_downgrade_max_model_confidence" in error for error in config.validate()))

    def test_describe_and_paths(self) -> None:
        self.write(BASE_CONFIG)
        config = load_config(self.path)
        info = config.describe()
        self.assertEqual(info["source"], "kafka")
        self.assertEqual(config.policy_path, self.root / "config" / "policies.json")
        self.assertTrue(str(config.audit_log_path).endswith("policy_audit.jsonl"))

    def test_yaml_requires_pyyaml(self) -> None:
        if importlib.util.find_spec("yaml") is not None:
            self.skipTest("PyYAML установлен: ветка с ошибкой недоступна")
        yaml_path = self.root / "config.yaml"
        yaml_path.write_text("source:\n  type: kafka\n", encoding="utf-8")
        with self.assertRaises(ConfigError):
            load_structured(yaml_path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_structured(self.root / "absent.json")


if __name__ == "__main__":
    unittest.main()

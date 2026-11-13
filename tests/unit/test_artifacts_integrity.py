"""Тесты целостности артефактов и порогов обучения из конфигурации."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import load_config
from siem_enricher.ml.registry import MANIFEST_NAME, ModelRegistry, build_manifest, verify_manifest
from tests import PROJECT_ROOT


class ManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "model"
        self.directory.mkdir(parents=True)
        (self.directory / "config.json").write_text("{}", encoding="utf-8")
        (self.directory / "model.safetensors").write_bytes(b"weights")

    def test_manifest_covers_files(self) -> None:
        manifest = build_manifest(self.directory)
        self.assertIn("config.json", manifest["files"])
        self.assertIn("model.safetensors", manifest["files"])

    def test_verify_ok(self) -> None:
        manifest = build_manifest(self.directory)
        (self.directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        self.assertTrue(verify_manifest(self.directory)["ok"])

    def test_tampering_is_detected(self) -> None:
        manifest = build_manifest(self.directory)
        (self.directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        (self.directory / "model.safetensors").write_bytes(b"tampered")
        result = verify_manifest(self.directory)
        self.assertFalse(result["ok"])
        self.assertIn("model.safetensors", result["mismatched"])

    def test_missing_file_is_detected(self) -> None:
        manifest = build_manifest(self.directory)
        (self.directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        (self.directory / "config.json").unlink()
        result = verify_manifest(self.directory)
        self.assertFalse(result["ok"])
        self.assertIn("config.json", result["missing"])


class RegistryManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._cwd = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self._cwd)
        self.base = Path("ml") / "artifacts"
        self.base.mkdir(parents=True)

    def make(self, name: str) -> Path:
        path = Path(self.tmp.name) / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "config.json").write_text("{}", encoding="utf-8")
        (path / "model.safetensors").write_bytes(b"weights")
        return path

    def test_register_writes_manifest_and_fingerprint(self) -> None:
        registry = ModelRegistry("default", self.base)
        record = registry.register(self.make("v1"), {})
        self.assertTrue((self.base / record["artifact"] / MANIFEST_NAME).exists())
        self.assertTrue(record["manifest_fingerprint"].startswith("sha256:"))

    def test_verify_reports_active_version(self) -> None:
        registry = ModelRegistry("default", self.base)
        record = registry.register(self.make("v1"), {})
        result = registry.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(result["version"], record["id"])


class TrainingConfigTest(unittest.TestCase):
    def test_thresholds_come_from_config(self) -> None:
        config = load_config(PROJECT_ROOT / "config" / "config.local.json")
        self.assertIsInstance(config.ml.training_min_gain, float)
        self.assertGreater(config.ml.training_regression_limit, 0)
        self.assertGreaterEqual(config.ml.training_min_rows, 1)
        self.assertGreaterEqual(config.ml.training_epochs, 1)


if __name__ == "__main__":
    unittest.main()

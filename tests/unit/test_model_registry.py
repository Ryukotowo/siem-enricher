"""Тесты реестра версий модели: регистрация, активная версия, откат."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.ml.registry import ACTIVE_NAME, ModelRegistry


class RegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "artifacts"
        self.base.mkdir(parents=True)
        self._cwd = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self._cwd)

    def make_artifact(self, name: str, marker: str) -> Path:
        path = Path(self.tmp.name) / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "config.json").write_text(json.dumps({"marker": marker}), encoding="utf-8")
        (path / "model.safetensors").write_bytes(marker.encode())
        return path

    def test_register_sets_active_and_materialises(self) -> None:
        registry = ModelRegistry("default", self.base)
        record = registry.register(self.make_artifact("v1", "first"), {"после": {"F1": 0.7}})
        self.assertEqual(registry.load()["active"], record["id"])
        active = registry.active_path() / "config.json"
        self.assertEqual(json.loads(active.read_text(encoding="utf-8"))["marker"], "first")

    def test_rollback_to_previous(self) -> None:
        registry = ModelRegistry("default", self.base)
        registry.register(self.make_artifact("v1", "first"), {"после": {"F1": 0.7}})
        registry.register(self.make_artifact("v2", "second"), {"после": {"F1": 0.8}})
        self.assertEqual(registry.active()["metrics"]["после"]["F1"], 0.8)
        version = registry.rollback()
        self.assertEqual(version["metrics"]["после"]["F1"], 0.7)
        active = registry.active_path() / "config.json"
        self.assertEqual(json.loads(active.read_text(encoding="utf-8"))["marker"], "first")

    def test_rollback_without_previous_fails(self) -> None:
        registry = ModelRegistry("default", self.base)
        registry.register(self.make_artifact("v1", "only"), {})
        with self.assertRaises(ValueError):
            registry.rollback()

    def test_rollback_records_audit(self) -> None:
        registry = ModelRegistry("default", self.base)
        registry.register(self.make_artifact("v1", "first"), {})
        registry.register(self.make_artifact("v2", "second"), {})
        registry.rollback()
        audit = Path(self.tmp.name) / "var" / "audit.jsonl"
        self.assertTrue(audit.exists())
        kinds = [json.loads(line)["kind"] for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertIn("model_rollback", kinds)

    def test_tenant_uses_own_directory(self) -> None:
        registry = ModelRegistry("org1", self.base)
        registry.register(self.make_artifact("v1", "org"), {})
        self.assertTrue((self.base / "org1" / ACTIVE_NAME).exists())
        self.assertFalse((self.base / ACTIVE_NAME).exists())

    def test_prune_keeps_limit(self) -> None:
        registry = ModelRegistry("default", self.base)
        for index in range(7):
            registry.register(self.make_artifact(f"a{index}", f"m{index}"), {})
        self.assertLessEqual(len(registry.versions()), 6)


if __name__ == "__main__":
    unittest.main()

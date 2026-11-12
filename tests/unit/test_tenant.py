"""Тесты разделения по организациям."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import ServiceConfig, load_config
from siem_enricher.ml.classifier import resolve_artifact_path
from siem_enricher.service import panel as panel_module
from siem_enricher.service.panel import _labels_path, _settings_path, current_tenant
from tests import PROJECT_ROOT


def make_config(tenant: str):
    config = load_config(PROJECT_ROOT / "config" / "config.local.json")
    config.service = ServiceConfig(tenant=tenant)
    return config


class TenantNameTest(unittest.TestCase):
    def test_default_when_empty(self) -> None:
        self.assertEqual(current_tenant(make_config("")), "default")

    def test_cyrillic_name_is_kept(self) -> None:
        self.assertEqual(current_tenant(make_config("ООО Ромашка")), "ооо-ромашка")

    def test_ascii_name_kept(self) -> None:
        self.assertEqual(current_tenant(make_config("org-1")), "org-1")


class App:
    def __init__(self, tenant: str) -> None:
        self.state = type("State", (), {})()
        self.state.config = make_config(tenant)


class PathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._cwd = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self._cwd)

    def test_default_labels_in_shared_file(self) -> None:
        path = _labels_path(App("default"))
        self.assertEqual(path, Path(self.tmp.name) / panel_module.LABELS_FILE)

    def test_tenant_labels_are_separated(self) -> None:
        first = _labels_path(App("org1"))
        second = _labels_path(App("org2"))
        self.assertNotEqual(first, second)
        self.assertIn("org1", str(first))

    def test_settings_are_separate_per_tenant(self) -> None:
        self.assertEqual(_settings_path(App("default")).name, "runtime-settings.json")
        self.assertEqual(_settings_path(App("org1")).name, "runtime-settings-org1.json")

    def test_artifact_is_taken_from_tenant_directory(self) -> None:
        scoped = Path("ml") / "artifacts" / "org1" / "sensitivity_feedback"
        scoped.mkdir(parents=True)
        (scoped / "config.json").write_text("{}", encoding="utf-8")
        shared = Path("ml") / "artifacts" / "sensitivity_transformer"
        shared.mkdir(parents=True)
        (shared / "config.json").write_text("{}", encoding="utf-8")
        self.assertEqual(resolve_artifact_path("auto", "org1"), scoped.resolve())
        self.assertEqual(resolve_artifact_path("auto", "default"), shared.resolve())


if __name__ == "__main__":
    unittest.main()

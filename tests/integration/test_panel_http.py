"""HTTP-тесты панели: коды ответов на изменяющих и читающих маршрутах."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from siem_enricher.config import load_config
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.metrics import reset_metrics, service_metrics
from siem_enricher.service.app import create_app
from tests import PROJECT_ROOT

HAS_HTTP = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)

if HAS_HTTP:
    from fastapi.testclient import TestClient  # noqa: E402
else:  # pragma: no cover - без extras сервис недоступен
    TestClient = None  # type: ignore[assignment]


def build_app(root: Path, api_key: str = "") -> tuple[TestClient, Path]:
    config = load_config(PROJECT_ROOT / "config" / "config.local.json")
    config.ml.type = "heuristic"
    config.ml.artifact_path = PROJECT_ROOT / "ml" / "artifacts" / "sensitivity_transformer"
    config.provenance.backend = "memory"
    config.policy.audit_log = str(root / "audit.jsonl")
    config.ml.rules_file = str(root / "rules.json")
    config.http.api_key = api_key
    (root / "rules.json").write_text(json.dumps({"directories": []}), encoding="utf-8")

    from siem_enricher.service import panel as panel_module

    panel_module.LABELS_FILE = str(root / "labels" / "analyst_labels.jsonl")
    panel_module.SETTINGS_FILE = str(root / "runtime-settings.json")

    reset_metrics()
    pipeline = EnrichmentPipeline.from_config(config, metrics=service_metrics())
    app = create_app(config, pipeline=pipeline, run_pipeline=False)
    return TestClient(app), root


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class PanelHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls._cwd = Path.cwd()
        os.chdir(cls.root)
        cls.client, cls.root = build_app(cls.root)

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._cwd)
        cls._tmp.cleanup()

    def test_health_and_ready(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        payload = self.client.get("/readyz").json()
        self.assertIn(payload["status"], {"ready", "not_ready"})

    def test_panel_page_renders(self) -> None:
        response = self.client.get("/ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("SIEM", response.text)

    def test_enrich_returns_event(self) -> None:
        response = self.client.post("/v1/enrich", json={
            "event_id": "http-1", "ts": "2026-11-13T09:00:00Z", "action": "read",
            "user": "petrov", "host": "ws-1",
            "path": r"C:\Бухгалтерия\Договор.docx",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("data_sensitivity", response.json())

    def test_label_and_export(self) -> None:
        labelled = self.client.post("/ui/label", json={
            "event_id": "http-1", "label": "confirmed",
            "path": r"C:\Бухгалтерия\Договор.docx", "level": "confidential",
        })
        self.assertEqual(labelled.status_code, 200)
        exported = self.client.get("/ui/labels/export")
        self.assertEqual(exported.status_code, 200)
        rows = [line for line in exported.text.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)

    def test_rules_reload_and_versions(self) -> None:
        self.assertEqual(self.client.post("/ui/rules/reload").status_code, 200)
        versions = self.client.get("/ui/rules/versions").json()["versions"]
        self.assertTrue(versions, "снимок правил должен появиться")
        rollback = self.client.post("/ui/rules/rollback", json={"version": versions[0]["name"]})
        self.assertEqual(rollback.status_code, 200)

    def test_state_capture_and_rollback(self) -> None:
        captured = self.client.post("/ui/state/capture", json={"note": "тест"})
        self.assertEqual(captured.status_code, 200)
        state = captured.json()["state"]
        listed = self.client.get("/ui/state").json()["states"]
        self.assertTrue(any(item["id"] == state["id"] for item in listed))
        rollback = self.client.post("/ui/state/rollback", json={"state": state["id"]})
        self.assertIn(rollback.status_code, {200, 400})

    def test_config_read_and_write(self) -> None:
        current = self.client.get("/ui/config")
        self.assertEqual(current.status_code, 200)
        updated = self.client.post("/ui/config", json={"values": {"risk.high": 0.65}})
        self.assertEqual(updated.status_code, 200)

    def test_unknown_state_returns_400(self) -> None:
        response = self.client.post("/ui/state/rollback", json={"state": "s19990101-000000"})
        self.assertEqual(response.status_code, 400)

    def test_metrics_endpoint(self) -> None:
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("siem_enricher_", response.text)


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class ApiKeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls._cwd = Path.cwd()
        os.chdir(cls.root)
        cls.client, cls.root = build_app(cls.root, api_key="secret-key")

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._cwd)
        cls._tmp.cleanup()

    def test_post_without_key_is_rejected(self) -> None:
        response = self.client.post("/v1/enrich", json={
            "event_id": "nokey", "ts": "2026-11-13T09:00:00Z", "action": "read",
            "user": "petrov", "host": "ws-1", "path": r"C:\data\file.docx",
        })
        self.assertEqual(response.status_code, 401)

    def test_post_with_key_is_allowed(self) -> None:
        response = self.client.post("/v1/enrich", json={
            "event_id": "withkey", "ts": "2026-11-13T09:00:00Z", "action": "read",
            "user": "petrov", "host": "ws-1", "path": r"C:\data\file.docx",
        }, headers={"X-API-Key": "secret-key"})
        self.assertEqual(response.status_code, 200)

    def test_wrong_key_is_rejected(self) -> None:
        response = self.client.post("/ui/rules/reload", headers={"X-API-Key": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_read_endpoints_stay_open(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/ui/events?limit=1").status_code, 200)


if __name__ == "__main__":
    unittest.main()

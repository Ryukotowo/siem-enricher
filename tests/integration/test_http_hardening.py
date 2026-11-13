"""Тесты защиты HTTP: лимит тела, валидация пакета, сценарий инцидента."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests.integration.test_panel_http import HAS_HTTP, build_app


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class BodyLimitTest(unittest.TestCase):
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

    def test_large_body_is_rejected_without_fastapi(self) -> None:
        if not HAS_HTTP:
            self.skipTest("нужен fastapi")
        big = {"event_id": "big", "pad": "x" * 2_100_000}
        response = self.client.post("/v1/enrich", json=big)
        self.assertEqual(response.status_code, 413)


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class BatchValidationTest(unittest.TestCase):
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

    def test_non_list_payload_rejected(self) -> None:
        response = self.client.post("/v1/enrich/batch", json={"events": "строка"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("массив", response.json()["detail"])

    def test_too_many_events_rejected(self) -> None:
        events = [{"event_id": str(index)} for index in range(501)]
        response = self.client.post("/v1/enrich/batch", json={"events": events})
        self.assertEqual(response.status_code, 422)
        self.assertIn("500", response.json()["detail"])

    def test_non_object_event_rejected(self) -> None:
        response = self.client.post("/v1/enrich/batch", json={"events": [1, 2, 3]})
        self.assertEqual(response.status_code, 422)


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class IncidentScenarioTest(unittest.TestCase):
    def test_incident_is_a_chain(self) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
        from generate_sample_events import build_events

        events = build_events(scenario="incident")
        self.assertEqual(len(events), 6)
        actions = [event["data"]["action"] for event in events]
        self.assertEqual(actions[0], "read")
        self.assertIn("archive", actions)
        self.assertIn("copy", actions)
        self.assertIn("upload", actions)
        stamps = [event["@timestamp"] for event in events]
        self.assertEqual(stamps, sorted(stamps))


if __name__ == "__main__":
    unittest.main()

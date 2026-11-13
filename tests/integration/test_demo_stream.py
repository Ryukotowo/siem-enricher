"""Тесты демонстрационного потока: заливка пачки и статус."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tests.integration.test_panel_http import HAS_HTTP, build_app

if HAS_HTTP:
    pass


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class DemoStreamTest(unittest.TestCase):
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

    def test_status_starts_stopped(self) -> None:
        payload = self.client.get("/ui/demo").json()
        self.assertFalse(payload["running"])

    def test_fill_adds_events(self) -> None:
        before = len(self.client.get("/ui/events?limit=500").json()["events"])
        result = self.client.post("/ui/demo/events", json={"count": 5}).json()
        self.assertTrue(result["ok"])
        self.assertEqual(result["sent"], 5)
        after = len(self.client.get("/ui/events?limit=500").json()["events"])
        self.assertGreater(after, before)

    def test_start_and_stop_stream(self) -> None:
        started = self.client.post("/ui/demo/start", json={"interval": 0.5}).json()
        self.assertTrue(started["ok"])
        self.assertTrue(self.client.get("/ui/demo").json()["running"])
        stopped = self.client.post("/ui/demo/stop", json={}).json()
        self.assertTrue(stopped["ok"])
        self.assertFalse(self.client.get("/ui/demo").json()["running"])


if __name__ == "__main__":
    unittest.main()

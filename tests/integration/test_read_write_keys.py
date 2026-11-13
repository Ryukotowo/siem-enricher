"""Тесты читающего и пишущего ключей."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tests.integration.test_panel_http import HAS_HTTP, build_app

if HAS_HTTP:
    pass  # noqa: E402


@unittest.skipUnless(HAS_HTTP, "нужны fastapi и httpx")
class ReadWriteKeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls._cwd = Path.cwd()
        os.chdir(cls.root)
        cls.client, cls.root = build_app(cls.root)
        cls.client.app.state.config.http.api_key = "write-key"
        cls.client.app.state.config.http.read_key = "read-key"

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._cwd)
        cls._tmp.cleanup()

    def test_read_key_allows_read(self) -> None:
        response = self.client.get("/ui/events?limit=1", headers={"X-API-Key": "read-key"})
        self.assertEqual(response.status_code, 200)

    def test_read_key_cannot_write(self) -> None:
        response = self.client.post("/ui/rules/reload", headers={"X-API-Key": "read-key"})
        self.assertEqual(response.status_code, 401)

    def test_write_key_allows_both(self) -> None:
        self.assertEqual(
            self.client.get("/ui/events?limit=1", headers={"X-API-Key": "write-key"}).status_code,
            200,
        )
        self.assertEqual(
            self.client.post("/ui/rules/reload", headers={"X-API-Key": "write-key"}).status_code,
            200,
        )

    def test_no_key_is_rejected_for_data(self) -> None:
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/ui/events?limit=1").status_code, 401)

    def test_monitoring_stays_open(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.client.get("/metrics").status_code, 200)

    def test_key_from_query_sets_cookie(self) -> None:
        response = self.client.get("/ui?key=read-key")
        self.assertEqual(response.status_code, 200)
        self.assertIn("siem_key", response.cookies)
        self.assertEqual(self.client.get("/ui/events?limit=1").status_code, 200)


if __name__ == "__main__":
    unittest.main()

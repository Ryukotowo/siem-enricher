"""Заглушка SIEM для демонстрации обратного коннектора."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

MAX_BODY_BYTES = 32 * 1024 * 1024


class EventStore:
    """Потокобезопасный приёмник событий."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.received = 0
        self.batches = 0
        self.errors = 0
        self.started_at = time.time()

    def store(self, payload: Any) -> int:
        documents = payload if isinstance(payload, list) else [payload]
        documents = [doc for doc in documents if isinstance(doc, dict)]
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                for document in documents:
                    handle.write(json.dumps(document, ensure_ascii=False, default=str) + "\n")
            self.received += len(documents)
            self.batches += 1
        return len(documents)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": "ok",
                "received": self.received,
                "batches": self.batches,
                "errors": self.errors,
                "uptime_seconds": round(time.time() - self.started_at, 3),
                "output": str(self.path),
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "MockSIEM/0.1"
    store: EventStore  # заполняется при создании сервера

    def _respond(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - имя задано базовым классом
        if self.path.startswith("/healthz"):
            self._respond(200, {"status": "ok"})
        elif self.path.startswith("/_stats"):
            self._respond(200, self.store.stats())
        else:
            self._respond(200, {
                "service": "mock-siem",
                "endpoints": ["POST /events", "GET /_stats", "GET /healthz"],
            })

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/events"):
            self._respond(404, {"error": "неизвестный путь", "path": self.path})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self.store.errors += 1
            self._respond(400, {"error": "некорректная длина тела запроса", "length": length})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.store.errors += 1
            self._respond(400, {"error": f"некорректный JSON: {exc}"})
            return
        accepted = self.store.store(payload)
        self._respond(200, {"accepted": accepted, "total": self.store.received})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Тихий лог: заглушка не должна засорять вывод демонстрации."""
        if "--verbose" in sys.argv:
            super().log_message(format, *args)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Заглушка SIEM: приём обогащённых событий по HTTP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--out", default="var/mock_siem_received.jsonl")
    parser.add_argument("--verbose", action="store_true", help="Логировать каждый запрос")
    args = parser.parse_args(argv)

    store = EventStore(Path(args.out))
    Handler.store = store
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Заглушка SIEM слушает http://{args.host}:{args.port}")
    print(f"Принятые события: {store.path}")
    print("Остановка: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка сервера...")
    finally:
        server.server_close()
        print(json.dumps(store.stats(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

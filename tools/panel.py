"""Панель аналитика поверх обогащённых событий (только стандартная библиотека).

Запуск:
    python tools/panel.py --input var/screens/replay_out.jsonl --port 8099

Открыть: http://127.0.0.1:8099/
Файл перечитывается при изменении, поэтому панель обновляется во время прогона.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src", ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from siem_enricher.service.panel import PANEL_HTML, EventBuffer, load_documents  # noqa: E402


class PanelState:
    def __init__(self, path: Path, limit: int) -> None:
        self.path = path
        self.limit = limit
        self.buffer = EventBuffer(500)
        self.mtime = 0.0
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = 0.0
        if force or mtime != self.mtime:
            self.buffer = EventBuffer(500)
            self.buffer.extend(load_documents(self.path))
            self.mtime = mtime


class Handler(BaseHTTPRequestHandler):
    state: PanelState

    def do_GET(self) -> None:  # noqa: N802 - имя задано базовым классом
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/ui"):
            self._send(200, "text/html; charset=utf-8", PANEL_HTML.encode("utf-8"))
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", [self.state.limit])[0])
            self.state.reload()
            payload = {"events": self.state.buffer.recent(limit), "stats": self.state.buffer.stats()}
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            return
        if parsed.path == "/healthz":
            self._send(200, "application/json", b'{"status":"ok"}')
            return
        self._send(404, "text/plain; charset=utf-8", "не найдено".encode("utf-8"))

    def _send(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Панель обогащённых событий")
    parser.add_argument("--input", default=str(ROOT / "var" / "screens" / "replay_out.jsonl"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()

    state = PanelState(Path(args.input), args.limit)
    Handler.state = state

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"панель: http://{args.host}:{args.port}/")
    print(f"событий загружено: {len(state.buffer.recent(500))} из {args.input}")
    print("Ctrl+C — остановить")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("остановлено")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

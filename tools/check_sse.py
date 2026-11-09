"""Проверка SSE: событие приходит в поток без опроса."""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8087"
POSITIVE = {"confidential", "secret"}


def main() -> int:
    received: list[dict] = []

    def listen() -> None:
        request = urllib.request.Request(BASE + "/ui/stream")
        with urllib.request.urlopen(request, timeout=40) as response:
            for raw in response:
                line = raw.decode("utf-8").strip()
                if line.startswith("data: "):
                    received.append(json.loads(line[6:]))
                    if len(received) >= 2:
                        return

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    time.sleep(1.5)

    events = [json.loads(line) for line in
              (ROOT / "var" / "experiment" / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()][:2]
    for event in events:
        data = json.dumps(event, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(BASE + "/v1/enrich", data=data,
                                        headers={"Content-Type": "application/json; charset=utf-8"})
        urllib.request.urlopen(request, timeout=30).read()

    thread.join(timeout=20)
    print(f"SSE получил событий: {len(received)}")
    for item in received:
        print(f"  {item.get('file')} | решение {item.get('decision')} | риск {item.get('risk')}")
    return 0 if received else 1


if __name__ == "__main__":
    raise SystemExit(main())

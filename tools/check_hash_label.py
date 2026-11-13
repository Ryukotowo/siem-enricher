"""Живая проверка: событие с именем-отпечатком показывает «название скрыто»."""

import json
import urllib.request

payload = {
    "event_id": "hash-check",
    "ts": "2026-11-13T11:00:00Z",
    "action": "read",
    "user": "ivanov",
    "host": "ws-1",
    "filename": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
}
request = urllib.request.Request(
    "http://127.0.0.1:8081/v1/enrich",
    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    headers={"Content-Type": "application/json; charset=utf-8"},
)
urllib.request.urlopen(request, timeout=30).read()

events = json.loads(urllib.request.urlopen(
    "http://127.0.0.1:8081/ui/events?limit=5", timeout=20).read().decode())["events"]
for item in events:
    if item.get("event_id") == "hash-check":
        print("файл:", item.get("file"))
        print("hash_only:", item.get("hash_only"))
        break
else:
    print("событие не попало в панель")

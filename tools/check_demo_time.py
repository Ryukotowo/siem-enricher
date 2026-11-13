import json
import time
import urllib.request


def post(path, body):
    request = urllib.request.Request(
        "http://127.0.0.1:8081" + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(request, timeout=60).read().decode())


post("/ui/demo/events", {"count": 10})
time.sleep(1)
data = json.loads(urllib.request.urlopen(
    "http://127.0.0.1:8081/ui/events?limit=10", timeout=30).read().decode())
print("stats:", data["stats"])
print("время событий (UTC из сервиса):")
for event in data["events"][:3]:
    print("  ", event["ts"], event["file"][:40])
print("сейчас UTC на машине:", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

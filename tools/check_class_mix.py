"""Распределение классов в генераторе и после обогащения."""

import json
import sys
from collections import Counter

sys.path.insert(0, "tools")

from generate_sample_events import build_events

events = build_events(scenario="mixed", count=100)
truth = Counter()
for event in events:
    truth[(event.get("x_ground_truth") or {}).get("sensitivity")] += 1
print("истина в генераторе:", dict(truth))

import urllib.request

data = json.loads(urllib.request.urlopen(
    "http://127.0.0.1:8081/ui/events?limit=500", timeout=20).read().decode())
got = Counter(event.get("sensitivity") for event in data["events"])
print("в панели сейчас:", dict(got))

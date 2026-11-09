"""Проверка тумблеров правил: выключение POL-008 меняет решения."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8087"


def post(path: str, payload: dict) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(BASE + path, data=data,
                                     headers={"Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    config = get("/ui/config")
    rules = config.get("rules") or []
    print(f"правил в панели: {len(rules)}; первые: {[r['id'] for r in rules[:4]]}")

    events = [json.loads(line) for line in
              (ROOT / "var" / "experiment" / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    target = None
    for event in events:
        document = post("/v1/enrich", event)
        if "POL-008" in (document.get("policy_rule_ids") or []):
            target = event
            before = document
            break
    if target is None:
        print("не нашёл событие с POL-008")
        return 1
    print(f"событие с POL-008: {before['file']['name']} -> решение {before['policy_decision']}")

    result = post("/ui/config", {"rules": {"POL-008": False}})
    print(f"выключение POL-008: {result['applied']}")

    after = post("/v1/enrich", target)
    print(f"после выключения: решение {after['policy_decision']}, "
          f"правила {after.get('policy_rule_ids')}")

    post("/ui/config", {"rules": {"POL-008": True}})
    restored = post("/v1/enrich", target)
    print(f"после включения обратно: решение {restored['policy_decision']}, "
          f"правила {restored.get('policy_rule_ids')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

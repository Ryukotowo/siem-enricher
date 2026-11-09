"""Проверка, что настройки из панели влияют на решения на лету."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8087"


def post(path: str, payload: dict) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        BASE + path, data=data, headers={"Content-Type": "application/json; charset=utf-8"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    event = json.loads((ROOT / "var" / "experiment" / "dataset.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])

    post("/ui/config", {"values": {"risk.critical": 0.85}})
    first = post("/v1/enrich", event)
    print(f"critical=0.85 -> риск {first['risk_score']:.2f}, уровень {first['risk_severity']}, "
          f"класс {first['data_sensitivity']}, решение {first['policy_decision']}")

    post("/ui/config", {"values": {"risk.high": 0.40, "risk.critical": 0.60}})
    second = post("/v1/enrich", event)
    print(f"high=0.40 -> риск {second['risk_score']:.2f}, уровень {second['risk_severity']}, "
          f"класс {second['data_sensitivity']}, решение {second['policy_decision']}")

    post("/ui/config", {"values": {"policy.mode": "live"}})
    third = post("/v1/enrich", event)
    print(f"политики live -> режим в документе {third.get('policy_mode')}, "
          f"действия {third.get('policy_actions')}")

    post("/ui/config", {"values": {"policy.mode": "dry_run", "risk.critical": 0.85}})
    values = get("/ui/config")["values"]
    print("после сброса:", {k: values[k] for k in ("risk.critical", "policy.mode")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

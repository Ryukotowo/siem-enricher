"""Исправление шаблона ссылки: Quickwit ожидает index_id."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ROOT / "var" / "panel-settings.json"

TEMPLATE = "http://localhost:7280/ui/search?index_id=siem-enriched&query=event_id:{event_id}"


def main() -> int:
    data = json.loads(SETTINGS.read_text(encoding="utf-8")) if SETTINGS.exists() else {}
    data["enabled"] = data.get("enabled", True)
    data["siem_url_template"] = TEMPLATE
    SETTINGS.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"шаблон: {TEMPLATE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

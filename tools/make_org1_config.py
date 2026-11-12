"""Конфигурация второй организации для проверки разделения данных."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher")
SOURCE = REPO / "config" / "config.local.json"
TARGET = REPO / "config" / "config.org1.json"


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    data["service"]["tenant"] = "org1"
    data["service"]["instance_id"] = "enricher-org1"
    data["provenance"]["sqlite_path"] = "var/state/provenance_org1.db"
    TARGET.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"создан {TARGET.name}: tenant=org1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

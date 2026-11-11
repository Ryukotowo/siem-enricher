"""Состояние сервиса в контейнере — на именованном томе (SQLite WAL не работает на bind-mount Windows)."""

from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "config.docker.json"
COMPOSE = ROOT / "docker-compose.yml"


def main() -> int:
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    data["provenance"]["sqlite_path"] = "${PROVENANCE_PATH:-/app/state/provenance.db}"
    data.setdefault("policy", {})["audit_log"] = "${AUDIT_LOG:-/app/state/policy_audit.jsonl}"
    CONFIG.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("config.docker.json: состояние перенесено в /app/state")

    text = COMPOSE.read_text(encoding="utf-8")
    if "state-data:/app/state" not in text:
        text = text.replace(
            "      - ./var:/app/var\n      - ./config:/app/config:ro\n      - ./ml/artifacts:/app/ml/artifacts:ro",
            "      - ./var:/app/var\n      - state-data:/app/state\n"
            "      - ./config:/app/config:ro\n      - ./ml/artifacts:/app/ml/artifacts:ro",
            1,
        )
        text = text.replace("volumes:\n  redpanda-data:", "volumes:\n  state-data:\n  redpanda-data:", 1)
        COMPOSE.write_text(text, encoding="utf-8")
        print("docker-compose.yml: добавлен том state-data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

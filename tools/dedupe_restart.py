"""Убрать дубли restart и оставить по одному на сервис."""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"
SERVICES = ["redpanda", "redis", "mock-siem", "quickwit", "opensearch",
            "prometheus", "grafana", "enricher"]


def main() -> int:
    lines = COMPOSE.read_text(encoding="utf-8").splitlines()
    cleaned: list[str] = []
    current = None
    for line in lines:
        stripped = line.strip()
        if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
            current = stripped.rstrip(":")
        if line.strip().startswith("restart:"):
            continue  # все существующие убираем, добавим ровно по одному
        cleaned.append(line)
        if current in SERVICES and line.strip().startswith("networks:"):
            cleaned.append("    restart: unless-stopped")
            current = None

    COMPOSE.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    restarts = sum(1 for line in cleaned if line.strip().startswith("restart:"))
    print(f"политик restart в файле: {restarts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Политика перезапуска для всех долгоживущих сервисов compose."""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

# сервисы, которым нужна политика (одноразовые init/демо — пропускаем)
LONG_RUNNING = [
    "redpanda", "redis", "mock-siem", "quickwit", "opensearch",
    "prometheus", "grafana", "enricher",
]


def main() -> int:
    lines = COMPOSE.read_text(encoding="utf-8").splitlines()
    added = 0
    result: list[str] = []
    current = None

    for line in lines:
        stripped = line.strip()
        if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
            current = stripped.rstrip(":")
        result.append(line)
        # вставляем политику сразу после healthcheck-блока нужного сервиса
        if current in LONG_RUNNING and stripped.startswith("networks:"):
            result.append("    restart: unless-stopped")
            added += 1
            current = None

    COMPOSE.write_text("\n".join(result) + "\n", encoding="utf-8")
    print(f"restart: unless-stopped добавлен сервисам: {added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

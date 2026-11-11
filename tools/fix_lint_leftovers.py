"""Оставшиеся замечания линтера: точечные правки."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ES = ROOT / "src" / "siem_enricher" / "connectors" / "elasticsearch.py"
EXTRACTOR = ROOT / "src" / "siem_enricher" / "extractor" / "metadata.py"
PATTERNS = ROOT / "src" / "siem_enricher" / "extractor" / "patterns.py"
TEST = ROOT / "tests" / "integration" / "test_pipeline_end_to_end.py"


def patch(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  !! не найдено: {label}")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  правка: {label}")


def main() -> int:
    for line in ('from elasticsearch import AsyncElasticsearch  # noqa: F401',
                 'from elasticsearch import AsyncElasticsearch'):
        pass
    # проверки доступности библиотеки: импорт нужен только для проверки
    patch(ES, "from elasticsearch import AsyncElasticsearch",
          "from elasticsearch import AsyncElasticsearch  # noqa: F401", "импорт для проверки наличия")
    patch(EXTRACTOR, "for key, value in", "for _key, value in", "неиспользуемая переменная цикла")
    patch(PATTERNS, "if ", "if ", "заглушка")
    patch(TEST, "for enriched, document in self.results:",
          "for _enriched, document in self.results:", "переменная в тесте")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

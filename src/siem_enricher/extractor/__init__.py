"""Извлечение метаданных события: файлы, пути, процессы, пользователи, сетевые адреса."""

from siem_enricher.extractor.metadata import (
    FIELD_ALIASES,
    ExtractedMetadata,
    MetadataExtractor,
)

__all__ = ["FIELD_ALIASES", "ExtractedMetadata", "MetadataExtractor"]

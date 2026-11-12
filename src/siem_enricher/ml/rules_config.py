"""Правила классификации из конфигурации: организация настраивает без кода.

Файл правил (по умолчанию ``config/rules.json``) позволяет:
- добавить свои каталоги, шаблоны имён и расширения;
- переопределить встроенное правило по ``id``;
- отключить правило флагом ``enabled: false``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from siem_enricher.ml.fallback_rules import (
    DIRECTORY_RULES,
    EXTENSION_RULES,
    FILENAME_RULES,
    KeywordRule,
    _rule,
)
from siem_enricher.models.enrichment import SensitivityLevel


@dataclass
class RulesSpec:
    """Набор правил, готовый к передаче в классификатор."""

    filename_rules: tuple[KeywordRule, ...]
    directory_rules: tuple[KeywordRule, ...]
    extension_rules: dict[str, tuple[SensitivityLevel, float, str]]
    source: Path | None = None
    errors: list[str] | None = None


def _parse_level(value: Any, default: SensitivityLevel) -> SensitivityLevel:
    return SensitivityLevel.from_value(str(value), default=default) if value else default


def _parse_keyword(item: dict[str, Any], default_level: SensitivityLevel) -> KeywordRule | None:
    rule_id = str(item.get("id") or "").strip()
    pattern = str(item.get("pattern") or "").strip()
    if not rule_id or not pattern:
        return None
    try:
        return _rule(
            rule_id,
            _parse_level(item.get("level"), default_level),
            float(item.get("weight", 1.0)),
            pattern,
            str(item.get("note") or f"правило {rule_id} из конфигурации"),
        )
    except Exception:  # noqa: BLE001 - некорректная регулярка не должна ломать сервис
        return None


def _merge(base: tuple[KeywordRule, ...], items: list[dict[str, Any]],
           default_level: SensitivityLevel, errors: list[str]) -> tuple[KeywordRule, ...]:
    by_id = {rule.name: rule for rule in base}
    order = [rule.name for rule in base]
    for item in items:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("id") or "").strip()
        if item.get("enabled") is False:
            by_id.pop(rule_id, None)
            continue
        rule = _parse_keyword(item, default_level)
        if rule is None:
            errors.append(f"правило {rule_id or '?'} пропущено: нужны id и pattern")
            continue
        if rule_id not in by_id:
            order.append(rule_id)
        by_id[rule_id] = rule
    return tuple(by_id[rule_id] for rule_id in order if rule_id in by_id)


def _merge_extensions(items: Any, errors: list[str]) -> dict[str, tuple[SensitivityLevel, float, str]]:
    result = dict(EXTENSION_RULES)
    if isinstance(items, dict):
        entries = [
            {"ext": ext, **(value if isinstance(value, dict) else {"weight": value})}
            for ext, value in items.items()
        ]
    elif isinstance(items, list):
        entries = [item for item in items if isinstance(item, dict)]
    else:
        return result

    for item in entries:
        ext = str(item.get("ext") or "").strip().lower()
        if not ext:
            continue
        if item.get("enabled") is False:
            result.pop(ext, None)
            continue
        if not ext.startswith("."):
            ext = "." + ext
        level = _parse_level(item.get("level"), SensitivityLevel.INTERNAL)
        try:
            weight = float(item.get("weight", 1.0))
        except (TypeError, ValueError):
            errors.append(f"расширение {ext}: вес должен быть числом")
            continue
        result[ext] = (level, weight, str(item.get("note") or f"расширение {ext}"))
    return result


def load_rules(path: str | Path | None) -> RulesSpec:
    """Прочитать правила из файла и наложить их на встроенные."""
    default = RulesSpec(
        filename_rules=FILENAME_RULES,
        directory_rules=DIRECTORY_RULES,
        extension_rules=dict(EXTENSION_RULES),
    )
    if not path:
        return default
    file_path = Path(path)
    if not file_path.exists():
        return default

    errors: list[str] = []
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return RulesSpec(default.filename_rules, default.directory_rules,
                         default.extension_rules, file_path, [f"файл правил не прочитан: {exc}"])

    if not isinstance(data, dict):
        return RulesSpec(default.filename_rules, default.directory_rules,
                         default.extension_rules, file_path, ["ожидался объект JSON"])

    filenames = _merge(default.filename_rules, data.get("filenames") or [],
                       SensitivityLevel.INTERNAL, errors)
    directories = _merge(default.directory_rules, data.get("directories") or [],
                         SensitivityLevel.INTERNAL, errors)
    extensions = _merge_extensions(data.get("extensions"), errors)
    return RulesSpec(filenames, directories, extensions, file_path, errors)


__all__ = ["RulesSpec", "load_rules"]

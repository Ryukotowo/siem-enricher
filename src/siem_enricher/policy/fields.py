"""Доступ к полям документа по путям вида ``files[*].path``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Sequence

_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\*|\d+)\]")


@dataclass(slots=True)
class Target:
    """Найденный элемент документа: контейнер, ключ и текущее значение."""

    container: Any
    key: Any
    value: Any

    def set(self, new_value: Any) -> None:
        if isinstance(self.container, dict):
            self.container[self.key] = new_value
        elif isinstance(self.container, list):
            self.container[int(self.key)] = new_value


def parse_path(path: str) -> list[str]:
    """Разобрать путь на токены: ``files[*].path`` -> ``['files', '*', 'path']``."""
    tokens: list[str] = []
    for name, index in _PATH_TOKEN_RE.findall(path or ""):
        token = name or index
        if token:
            tokens.append(token)
    return tokens


def _value(parent: Any, key: Any, root: Any) -> Any:
    if parent is None:
        return root
    if isinstance(parent, Mapping):
        return parent.get(key)
    if isinstance(parent, (list, tuple)) and isinstance(key, int):
        return parent[key] if 0 <= key < len(parent) else None
    return None


def iter_targets(document: Any, path: str) -> Iterator[Target]:
    """Перебрать все элементы документа, соответствующие пути."""
    tokens = parse_path(path)
    if not tokens:
        return
    stack: list[tuple[Any, Any]] = [(None, None)]
    for index, token in enumerate(tokens):
        last = index == len(tokens) - 1
        next_stack: list[tuple[Any, Any]] = []
        for parent, key in stack:
            value = _value(parent, key, document)
            if token == "*":
                if isinstance(value, dict):
                    items = list(value.keys())
                elif isinstance(value, (list, tuple)):
                    items = list(range(len(value)))
                else:
                    continue
                for item_key in items:
                    if last:
                        yield Target(value, item_key, value[item_key])
                    else:
                        next_stack.append((value, item_key))
            elif token.isdigit() and isinstance(value, (list, tuple)):
                item_key = int(token)
                if item_key < len(value):
                    if last:
                        yield Target(value, item_key, value[item_key])
                    else:
                        next_stack.append((value, item_key))
            else:
                if isinstance(value, Mapping) and token in value:
                    if last:
                        yield Target(value, token, value[token])
                    else:
                        next_stack.append((value, token))
        stack = next_stack
        if not stack:
            break


def get_values(document: Any, path: str) -> list[Any]:
    """Значения по пути (для условий правил)."""
    return [target.value for target in iter_targets(document, path)]


def get_first(document: Any, path: str, default: Any = None) -> Any:
    for value in get_values(document, path):
        return value
    return default


def set_values(
    document: Any,
    path: str,
    new_value: Any = None,
    transform: Any = None,
) -> list[str]:
    """Установить значение по пути."""
    changed: list[str] = []
    for index, target in enumerate(iter_targets(document, path)):
        if transform is not None:
            replacement = transform(target.value)
        else:
            replacement = new_value
        target.set(replacement)
        changed.append(f"{path}[{index}]" if "*" in path else path)
    return changed


def has_path(document: Any, path: str) -> bool:
    return any(True for _ in iter_targets(document, path))


def flatten(document: Mapping[str, Any], prefix: str = "", max_depth: int = 6) -> dict[str, Any]:
    """Плоское представление документа — удобно для отладки правил и журнала аудита."""
    result: dict[str, Any] = {}

    def walk(node: Any, current: str, depth: int) -> None:
        if depth > max_depth:
            result[current] = "<...>"
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                walk(value, f"{current}.{key}" if current else str(key), depth + 1)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node[:16]):
                walk(value, f"{current}[{index}]", depth + 1)
        else:
            result[current] = node

    walk(document, prefix, 0)
    return result


def collect_missing(document: Any, paths: Sequence[str]) -> list[str]:
    """Пути, которые не найдены в документе (для валидации правил)."""
    return [path for path in paths if not has_path(document, path)]

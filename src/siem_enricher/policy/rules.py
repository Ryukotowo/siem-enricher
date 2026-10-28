"""Декларативные правила применения политик."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from siem_enricher.config import ConfigError, load_structured
from siem_enricher.logging_setup import get_logger
from siem_enricher.models.enums import ActionType, PolicyDecision, SensitivityLevel, Severity
from siem_enricher.policy.fields import get_values

logger = get_logger("policy.rules")

COMPARISON_OPS = frozenset({"eq", "ne", "in", "not_in", "gte", "gt", "lte", "lt"})
STRING_OPS = frozenset({"contains", "not_contains", "regex", "not_regex"})
EXISTENCE_OPS = frozenset({"exists", "missing"})
LENGTH_OPS = frozenset({"len_gte", "len_lte"})
SUPPORTED_OPS = COMPARISON_OPS | STRING_OPS | EXISTENCE_OPS | LENGTH_OPS


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().replace(",", "."))
        except ValueError:
            return None
    return None


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _sensitivity_rank(value: Any) -> int | None:
    """Ранг класса конфиденциальности, если значение распознано как класс."""
    if isinstance(value, SensitivityLevel):
        return value.rank
    if isinstance(value, str):
        text = value.strip().lower()
        if text == SensitivityLevel.UNKNOWN.value:
            return None
        level = SensitivityLevel.from_value(text, default=None)
        if level is not SensitivityLevel.UNKNOWN:
            return level.rank
    return None


def _severity_rank(value: Any) -> int | None:
    if isinstance(value, Severity):
        return value.rank
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {s.value for s in Severity}:
            return Severity(text).rank
    return None


def _apply_order(left: float, right: float, op: str) -> bool:
    if op == "gte":
        return left >= right
    if op == "gt":
        return left > right
    if op == "lte":
        return left <= right
    if op == "lt":
        return left < right
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    return False


def compare_scalar(actual: Any, expected: Any, op: str) -> bool:
    """Сравнить два значения с учётом их типа (число, класс, уровень, время, строка)."""
    if actual is None:
        return op in {"ne", "not_in"}

    left, right = _as_float(actual), _as_float(expected)
    if left is not None and right is not None:
        return _apply_order(left, right, op)

    left_rank, right_rank = _sensitivity_rank(actual), _sensitivity_rank(expected)
    if left_rank is not None and right_rank is not None:
        return _apply_order(left_rank, right_rank, op)

    left_sev, right_sev = _severity_rank(actual), _severity_rank(expected)
    if left_sev is not None and right_sev is not None:
        return _apply_order(left_sev, right_sev, op)

    left_dt, right_dt = _as_datetime(actual), _as_datetime(expected)
    if left_dt is not None and right_dt is not None:
        return _apply_order(left_dt.timestamp(), right_dt.timestamp(), op)

    left_text = str(actual).strip().casefold()
    right_text = str(expected).strip().casefold()
    if op == "eq":
        return left_text == right_text
    if op == "ne":
        return left_text != right_text
    return False


def _matches(condition: Condition, document: Mapping[str, Any]) -> bool:
    """Проверить условие по документу (семантика «существует значение, удовлетворяющее условию»)."""
    values = get_values(document, condition.field)
    op = condition.op.lower()
    if op == "exists":
        return bool(values) and any(value is not None for value in values)
    if op == "missing":
        return not values or all(value is None for value in values)
    if not values:
        return False

    expected = condition.value
    expected_list = list(expected) if isinstance(expected, (list, tuple, set)) else [expected]

    for value in values:
        if op == "in":
            if any(compare_scalar(value, item, "eq") for item in expected_list):
                return True
        elif op == "not_in":
            if all(not compare_scalar(value, item, "eq") for item in expected_list):
                return True
        elif op == "contains":
            if any(str(item).casefold() in str(value).casefold() for item in expected_list):
                return True
        elif op == "not_contains":
            if all(str(item).casefold() not in str(value).casefold() for item in expected_list):
                return True
        elif op == "regex":
            if any(_safe_search(item, value) for item in expected_list):
                return True
        elif op == "not_regex":
            if all(not _safe_search(item, value) for item in expected_list):
                return True
        elif op == "len_gte":
            if _safe_len(value) >= float(expected):
                return True
        elif op == "len_lte":
            if _safe_len(value) <= float(expected):
                return True
        elif compare_scalar(value, expected, op):
            return True
    return False


def _safe_search(pattern: Any, value: Any) -> bool:
    try:
        return bool(re.search(str(pattern), str(value), re.IGNORECASE | re.UNICODE))
    except re.error as exc:
        logger.warning("Некорректное регулярное выражение в правиле",
                       extra={"pattern": str(pattern), "reason": str(exc)})
        return False


def _safe_len(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return len(str(value))


@dataclass(slots=True)
class Condition:
    """Атомарное условие над полем документа."""

    field: str
    op: str
    value: Any = None

    def evaluate(self, document: Mapping[str, Any]) -> tuple[bool, list[str]]:
        """Проверить условие. Возвращает результат и текстовое обоснование."""
        try:
            matched = _matches(self, document)
        except Exception as exc:  # noqa: BLE001 - ошибка условия не должна ронять конвейер
            logger.warning("Ошибка вычисления условия правила",
                           extra={"condition": self.describe(), "reason": str(exc)})
            return False, [f"ошибка условия {self.describe()}: {exc}"]
        return (True, [self.describe()]) if matched else (False, [])

    def describe(self) -> str:
        if self.op in EXISTENCE_OPS:
            return f"{self.field} {self.op}"
        return f"{self.field} {self.op} {self.value!r}"


@dataclass(slots=True)
class ConditionGroup:
    """Группа условий: ``all`` (И), ``any`` (ИЛИ), ``not`` (НЕ)."""

    mode: str = "all"
    conditions: list[Condition | ConditionGroup] = field(default_factory=list)

    def evaluate(self, document: Mapping[str, Any]) -> tuple[bool, list[str]]:
        """Проверить группу условий. Возвращает результат и перечень выполненных условий."""
        if not self.conditions:
            return True, []
        results = [condition.evaluate(document) for condition in self.conditions]

        if self.mode == "all":
            matched = all(result for result, _ in results)
        elif self.mode == "any":
            matched = any(result for result, _ in results)
        elif self.mode == "not":
            matched = not any(result for result, _ in results)
        else:
            raise ConfigError(f"Неизвестный режим группы условий: {self.mode!r}")

        reasons = [reason for result, item_reasons in results if result for reason in item_reasons]
        if not matched and self.mode in {"all", "any"}:
            reasons = [c.describe() for c in self.conditions if isinstance(c, Condition)]
        return matched, reasons

    def describe(self) -> str:
        parts = [c.describe() for c in self.conditions]
        if self.mode == "all":
            return " И ".join(parts)
        if self.mode == "any":
            return " ИЛИ ".join(parts)
        return "НЕ (" + " ИЛИ ".join(parts) + ")"

    def fields(self) -> list[str]:
        """Все поля, упомянутые в группе (для валидации правил)."""
        result: list[str] = []
        for condition in self.conditions:
            if isinstance(condition, ConditionGroup):
                result.extend(condition.fields())
            else:
                result.append(condition.field)
        return result


@dataclass(slots=True)
class ActionSpec:
    """Описание действия политики."""

    type: ActionType
    params: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        if self.type is ActionType.MASK_FIELD:
            return f"маскирование полей {self.params.get('fields')} ({self.params.get('strategy', 'hash')})"
        if self.type is ActionType.ALERT:
            return f"алерт ({self.params.get('severity', 'medium')})"
        if self.type is ActionType.BLOCK:
            return f"блокировка ({self.params.get('target', 'process')})"
        if self.type is ActionType.TAG:
            return f"тег {self.params.get('value')}"
        return self.type.value


@dataclass(slots=True)
class PolicyRule:
    """Правило применения политики."""

    id: str
    title: str = ""
    description: str = ""
    enabled: bool = True
    priority: int = 0
    severity: Severity = Severity.MEDIUM
    tags: list[str] = field(default_factory=list)
    when: ConditionGroup = field(default_factory=ConditionGroup)
    then: list[ActionSpec] = field(default_factory=list)

    @property
    def decision(self) -> PolicyDecision:
        """Итоговое решение правила выводится из набора действий."""
        types = {spec.type for spec in self.then}
        if ActionType.BLOCK in types:
            return PolicyDecision.BLOCK
        if ActionType.MASK_FIELD in types:
            return PolicyDecision.MASK
        if ActionType.ALERT in types or ActionType.NOTIFY in types:
            return PolicyDecision.ALERT
        if ActionType.TAG in types:
            return PolicyDecision.TAG
        return PolicyDecision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "severity": self.severity.value,
            "decision": self.decision.value,
            "tags": list(self.tags),
            "when": self.when.describe(),
            "then": [spec.describe() for spec in self.then],
        }


def parse_conditions(node: Any, rule_id: str = "") -> ConditionGroup:
    """Разобрать секцию ``when`` правила."""
    if node is None:
        return ConditionGroup(mode="all", conditions=[])
    if not isinstance(node, Mapping):
        raise ConfigError(f"Правило {rule_id}: секция when должна быть объектом")

    for mode in ("all", "any", "not"):
        if mode in node:
            children = node[mode]
            if not isinstance(children, (list, tuple)):
                raise ConfigError(f"Правило {rule_id}: when.{mode} должен быть списком")
            parsed: list[Condition | ConditionGroup] = []
            for child in children:
                parsed.append(
                    parse_conditions(child, rule_id) if _is_group(child) else parse_condition(child, rule_id)
                )
            return ConditionGroup(mode=mode, conditions=parsed)

    if "field" in node:
        return ConditionGroup(mode="all", conditions=[parse_condition(node, rule_id)])

    raise ConfigError(f"Правило {rule_id}: не удалось разобрать секцию when: {node!r}")


def _is_group(node: Any) -> bool:
    return isinstance(node, Mapping) and any(mode in node for mode in ("all", "any", "not"))


def parse_condition(node: Mapping[str, Any], rule_id: str = "") -> Condition:
    """Разобрать одно условие."""
    field_name = str(node.get("field", "")).strip()
    op = str(node.get("op", "eq")).strip().lower()
    if not field_name:
        raise ConfigError(f"Правило {rule_id}: в условии не задано поле")
    if op not in SUPPORTED_OPS:
        raise ConfigError(
            f"Правило {rule_id}: неподдерживаемый оператор {op!r}. "
            f"Допустимо: {', '.join(sorted(SUPPORTED_OPS))}"
        )
    return Condition(field=field_name, op=op, value=node.get("value"))


def parse_action(node: Mapping[str, Any], rule_id: str = "") -> ActionSpec:
    """Разобрать действие правила."""
    try:
        action_type = ActionType.from_value(node.get("type"))
    except ValueError as exc:
        raise ConfigError(f"Правило {rule_id}: {exc}") from exc
    params = {k: v for k, v in node.items() if k != "type"}
    if action_type is ActionType.MASK_FIELD and not params.get("fields"):
        raise ConfigError(f"Правило {rule_id}: действие mask_field требует параметр fields")
    if action_type is ActionType.TAG and not params.get("value"):
        raise ConfigError(f"Правило {rule_id}: действие tag требует параметр value")
    return ActionSpec(type=action_type, params=params)


def parse_rule(node: Mapping[str, Any]) -> PolicyRule:
    """Разобрать одно правило политики."""
    rule_id = str(node.get("id", "")).strip()
    if not rule_id:
        raise ConfigError("У правила политики отсутствует поле id")
    then_nodes = node.get("then") or []
    if not isinstance(then_nodes, (list, tuple)):
        raise ConfigError(f"Правило {rule_id}: секция then должна быть списком")
    actions = [parse_action(item, rule_id) for item in then_nodes if isinstance(item, Mapping)]
    if not actions:
        raise ConfigError(f"Правило {rule_id}: секция then пуста")
    return PolicyRule(
        id=rule_id,
        title=str(node.get("title", "")),
        description=str(node.get("description", "")),
        enabled=bool(node.get("enabled", True)),
        priority=int(node.get("priority", 0)),
        severity=Severity.from_value(node.get("severity"), default=Severity.MEDIUM),
        tags=[str(t) for t in node.get("tags", [])],
        when=parse_conditions(node.get("when"), rule_id),
        then=actions,
    )


def load_rules(path: str | Path) -> list[PolicyRule]:
    """Загрузить набор правил из JSON/YAML-файла, упорядоченный по приоритету."""
    data = load_structured(path)
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ConfigError(f"Файл правил {path} не содержит списка 'rules'")
    rules: list[PolicyRule] = []
    seen: set[str] = set()
    for item in raw_rules:
        if not isinstance(item, Mapping):
            raise ConfigError(f"Файл правил {path}: элемент списка rules должен быть объектом")
        rule = parse_rule(item)
        if rule.id in seen:
            raise ConfigError(f"Файл правил {path}: дублирующийся идентификатор правила {rule.id}")
        seen.add(rule.id)
        rules.append(rule)
    rules.sort(key=lambda r: r.priority, reverse=True)
    logger.info("Загружены правила политик", extra={"count": len(rules), "path": str(path)})
    return rules


def validate_rules(rules: Sequence[PolicyRule]) -> list[str]:
    """Проверить набор правил на типовые ошибки конфигурации."""
    problems: list[str] = []
    for rule in rules:
        if not rule.then:
            problems.append(f"{rule.id}: нет действий")
        if rule.severity is Severity.LOW and rule.decision is PolicyDecision.BLOCK:
            problems.append(f"{rule.id}: блокировка с уровнем low — вероятно, ошибка приоритета")
        if not rule.when.conditions:
            problems.append(f"{rule.id}: пустое условие when — правило сработает на всех событиях")
        for spec in rule.then:
            mode = spec.params.get("mode")
            if spec.type is ActionType.BLOCK and mode not in {None, "dry_run", "live"}:
                problems.append(f"{rule.id}: недопустимый режим блокировки {mode!r}")
    return problems

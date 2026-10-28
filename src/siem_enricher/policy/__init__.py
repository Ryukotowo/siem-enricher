"""Модуль применения политик: маскирование, алертинг, блокировка."""

from siem_enricher.policy.actions import (
    ActionContext,
    ActionExecutor,
    ActionFactory,
    AlertExecutor,
    BlockExecutorAction,
    MaskFieldExecutor,
    NotifyExecutor,
    QuarantineExecutor,
    TagExecutor,
    mask_value,
)
from siem_enricher.policy.blockers import (
    BlockExecutor,
    BlockResult,
    DryRunBlocker,
    WazuhActiveResponseBlocker,
    WebhookBlocker,
    build_blocker,
)
from siem_enricher.policy.engine import PolicyEngine, PolicyEvaluation
from siem_enricher.policy.fields import Target, get_first, get_values, iter_targets, set_values
from siem_enricher.policy.rules import (
    ActionSpec,
    Condition,
    ConditionGroup,
    PolicyRule,
    load_rules,
    parse_rule,
    validate_rules,
)

__all__ = [
    "ActionContext",
    "ActionExecutor",
    "ActionFactory",
    "ActionSpec",
    "AlertExecutor",
    "BlockExecutor",
    "BlockExecutorAction",
    "BlockResult",
    "Condition",
    "ConditionGroup",
    "DryRunBlocker",
    "MaskFieldExecutor",
    "NotifyExecutor",
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyRule",
    "QuarantineExecutor",
    "TagExecutor",
    "Target",
    "WazuhActiveResponseBlocker",
    "WebhookBlocker",
    "build_blocker",
    "get_first",
    "get_values",
    "iter_targets",
    "load_rules",
    "mask_value",
    "parse_rule",
    "set_values",
    "validate_rules",
]

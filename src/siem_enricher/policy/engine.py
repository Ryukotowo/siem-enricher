"""Движок применения политик к обогащённым событиям."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from siem_enricher.audit import AuditLogger
from siem_enricher.config import AppConfig
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.enrichment import PolicyOutcome
from siem_enricher.models.enums import ActionType, PolicyDecision, Severity
from siem_enricher.policy.actions import DEFAULT_FACTORY, ActionContext, ActionFactory
from siem_enricher.policy.blockers import BlockExecutor, build_blocker
from siem_enricher.policy.rules import ActionSpec, PolicyRule, load_rules, validate_rules

logger = get_logger("policy.engine")


@dataclass(slots=True)
class PolicyEvaluation:
    """Результат применения политик к одному событию."""

    outcomes: list[PolicyOutcome] = field(default_factory=list)
    decision: PolicyDecision = PolicyDecision.ALLOW
    masked_fields: list[str] = field(default_factory=list)
    skipped_rules: list[str] = field(default_factory=list)
    evaluated_rules: int = 0
    mode: str = "dry_run"

    @property
    def triggered(self) -> list[PolicyOutcome]:
        return self.outcomes

    @property
    def rule_ids(self) -> list[str]:
        return [outcome.rule_id for outcome in self.outcomes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "mode": self.mode,
            "evaluated_rules": self.evaluated_rules,
            "skipped_rules": list(self.skipped_rules),
            "masked_fields": list(self.masked_fields),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


class PolicyEngine:
    """Применяет декларативные правила к документу обогащённого события."""

    def __init__(
        self,
        rules: Sequence[PolicyRule],
        mode: str = "dry_run",
        audit: AuditLogger | None = None,
        factory: ActionFactory | None = None,
        stop_on_block: bool = True,
        metrics: ServiceMetrics | None = None,
        webhook_url: str | None = None,
        blocker: BlockExecutor | None = None,
        tokenize_secret: str = "",
        rules_path: str | Path | None = None,
    ) -> None:
        self.rules = sorted(rules, key=lambda rule: rule.priority, reverse=True)
        self.mode = mode
        self.audit = audit
        self.factory = factory or DEFAULT_FACTORY
        self.stop_on_block = stop_on_block
        self.metrics = metrics
        self.webhook_url = webhook_url
        self.blocker = blocker
        self.tokenize_secret = tokenize_secret
        self.rules_path = Path(rules_path) if rules_path else None

    @classmethod
    def from_config(
        cls,
        config: AppConfig,
        metrics: ServiceMetrics | None = None,
        blocker: BlockExecutor | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> PolicyEngine:
        """Создать движок по конфигурации сервиса."""
        env = os.environ if environ is None else environ
        policy = config.policy
        audit = AuditLogger(config.audit_log_path)
        webhook_url = policy.webhook_url or env.get("POLICY_WEBHOOK_URL", "")
        if blocker is None:
            blocker = build_blocker(
                mode=policy.mode,
                webhook_url=webhook_url,
                wazuh_api_url=env.get("WAZUH_API_URL", ""),
                wazuh_user=env.get("WAZUH_API_USER", ""),
                wazuh_password=env.get("WAZUH_API_PASSWORD", ""),
            )
        rules = load_rules(config.policy_path)
        problems = validate_rules(rules)
        for problem in problems:
            logger.warning("Замечание к правилу политики", extra={"problem": problem})
        return cls(
            rules=rules,
            mode=policy.mode,
            audit=audit,
            stop_on_block=policy.stop_on_block,
            metrics=metrics,
            webhook_url=webhook_url,
            blocker=blocker,
            tokenize_secret=env.get("POLICY_TOKEN_SECRET", ""),
            rules_path=config.policy_path,
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        mode: str = "dry_run",
        audit_path: str | Path | None = None,
        webhook_url: str | None = None,
        metrics: ServiceMetrics | None = None,
        blocker: BlockExecutor | None = None,
        tokenize_secret: str = "",
    ) -> PolicyEngine:
        """Создать движок по файлу правил (используется в тестах и CLI)."""
        return cls(
            rules=load_rules(path),
            mode=mode,
            audit=AuditLogger(audit_path) if audit_path else None,
            metrics=metrics,
            webhook_url=webhook_url,
            blocker=blocker,
            tokenize_secret=tokenize_secret,
            rules_path=path,
        )

    def evaluate(self, document: Mapping[str, Any], apply_actions: bool = True) -> PolicyEvaluation:
        """Применить правила к документу обогащённого события."""
        mutable: dict[str, Any] = document if isinstance(document, dict) else dict(document)
        evaluation = PolicyEvaluation(decision=PolicyDecision.ALLOW, mode=self.mode)

        # Фаза 1: проверка условий
        matches: list[tuple[PolicyRule, list[str]]] = []
        stopped = False
        for rule in self.rules:
            if not rule.enabled:
                continue
            if stopped:
                evaluation.skipped_rules.append(rule.id)
                continue
            evaluation.evaluated_rules += 1
            matched, reasons = rule.when.evaluate(mutable)
            if not matched:
                continue
            matches.append((rule, reasons))
            if rule.decision is PolicyDecision.BLOCK and self.stop_on_block:
                stopped = True

        # Фаза 2: выполнение действий (маскирование отложено)
        deferred_masking: list[tuple[PolicyOutcome, list[ActionSpec]]] = []
        for rule, reasons in matches:
            outcome = PolicyOutcome(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                decision=rule.decision,
                reasons=reasons,
                tags=list(rule.tags),
                priority=rule.priority,
            )
            evaluation.outcomes.append(outcome)
            if not apply_actions:
                continue
            context = self._context(mutable, rule.id)
            masking = [spec for spec in rule.then if spec.type is ActionType.MASK_FIELD]
            others = [spec for spec in rule.then if spec.type is not ActionType.MASK_FIELD]
            if others:
                actions, _ = self.factory.execute_all(others, mutable, context)
                outcome.actions.extend(actions)
            if masking:
                deferred_masking.append((outcome, masking))

        for outcome, masking in deferred_masking:
            actions, masked = self.factory.execute_all(masking, mutable, self._context(mutable, outcome.rule_id))
            outcome.actions.extend(actions)
            evaluation.masked_fields.extend(masked)

        # Фаза 3: решения, метрики, аудит
        for outcome in evaluation.outcomes:
            if outcome.decision.rank > evaluation.decision.rank:
                evaluation.decision = outcome.decision
            if self.metrics is not None:
                self.metrics.policy_triggered.inc(
                    {
                        "rule_id": outcome.rule_id,
                        "decision": outcome.decision.value,
                        "severity": outcome.severity.value,
                    }
                )
            if self.audit is not None:
                self.audit.write(
                    {
                        "kind": "policy_decision",
                        "rule_id": outcome.rule_id,
                        "title": outcome.title,
                        "decision": outcome.decision.value,
                        "severity": outcome.severity.value,
                        "priority": outcome.priority,
                        "mode": self.mode,
                        "event_id": mutable.get("event_id"),
                        "data_sensitivity": mutable.get("data_sensitivity"),
                        "risk_score": mutable.get("risk_score"),
                        "reasons": outcome.reasons,
                        "actions": [action.to_dict() for action in outcome.actions],
                    }
                )

        evaluation.masked_fields = sorted(set(evaluation.masked_fields))
        logger.debug(
            "Политики применены",
            extra={
                "decision": evaluation.decision.value,
                "triggered": evaluation.rule_ids,
                "evaluated": evaluation.evaluated_rules,
                "skipped": evaluation.skipped_rules,
            },
        )
        return evaluation

    def _context(self, document: Mapping[str, Any], rule_id: str) -> ActionContext:
        """Контекст выполнения действий для правила."""
        return ActionContext(
            mode=self.mode,
            audit=self.audit,
            webhook_url=self.webhook_url,
            blocker=self.blocker,
            tokenize_secret=self.tokenize_secret,
            metrics=self.metrics,
            event_id=str(document.get("event_id") or "") or None,
            rule_id=rule_id,
        )

    def rules_summary(self) -> list[dict[str, Any]]:
        """Краткое описание правил (для API ``/v1/policies``)."""
        return [rule.to_dict() for rule in self.rules]

    def severity_of(self, rule_id: str) -> Severity:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule.severity
        return Severity.LOW

    def reload(self) -> int:
        """Перечитать правила из файла (горячая перезагрузка без перезапуска сервиса)."""
        if self.rules_path is None:
            raise RuntimeError("Движок создан без файла правил: перезагрузка невозможна")
        self.rules = load_rules(self.rules_path)
        logger.info("Правила политик перезагружены", extra={"count": len(self.rules), "path": str(self.rules_path)})
        return len(self.rules)


__all__ = ["PolicyEngine", "PolicyEvaluation"]

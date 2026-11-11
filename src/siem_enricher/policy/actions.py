"""Действия политик: маскирование полей, алертинг, теги, блокировка."""

from __future__ import annotations

import hashlib
import hmac
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from siem_enricher.audit import AuditLogger
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics
from siem_enricher.models.enrichment import ActionOutcome
from siem_enricher.models.enums import ActionStatus, ActionType
from siem_enricher.policy.blockers import BlockExecutor, DryRunBlocker
from siem_enricher.policy.fields import iter_targets
from siem_enricher.policy.rules import ActionSpec

logger = get_logger("policy.actions")


@dataclass(slots=True)
class ActionContext:
    """Контекст выполнения действий для одного срабатывания правила."""

    mode: str = "dry_run"
    audit: AuditLogger | None = None
    webhook_url: str | None = None
    blocker: BlockExecutor | None = None
    tokenize_secret: str = ""
    timeout_seconds: float = 5.0
    metrics: ServiceMetrics | None = None
    event_id: str | None = None
    rule_id: str | None = None

    @property
    def dry_run(self) -> bool:
        return self.mode != "live"

    def with_rule(self, rule_id: str) -> ActionContext:
        """Копия контекста с указанием правила (для журнала аудита)."""
        return ActionContext(
            mode=self.mode,
            audit=self.audit,
            webhook_url=self.webhook_url,
            blocker=self.blocker,
            tokenize_secret=self.tokenize_secret,
            timeout_seconds=self.timeout_seconds,
            metrics=self.metrics,
            event_id=self.event_id,
            rule_id=rule_id,
        )


def mask_value(value: str, strategy: str = "hash", secret: str = "") -> str:
    """Замаскировать значение согласно стратегии."""
    if not value:
        return value
    if strategy == "redact":
        return "***"
    if strategy == "tokenize":
        key = (secret or "siem-enricher").encode("utf-8")
        digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"tok_{digest[:16]}"
    if strategy == "partial":
        if len(value) < 6:
            return "***"
        return f"{value[:3]}***{value[-3:]}"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


class ActionExecutor(ABC):
    """Базовый исполнитель действия политики."""

    type: ActionType

    @abstractmethod
    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        """Выполнить действие и вернуть результат."""

    def _record_metric(self, context: ActionContext, outcome: ActionOutcome) -> None:
        if context.metrics is not None:
            context.metrics.policy_actions.inc({"type": outcome.type.value, "status": outcome.status.value})


class MaskFieldExecutor(ActionExecutor):
    """Маскирование значений полей обогащённого события."""

    type = ActionType.MASK_FIELD

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        fields = [str(f) for f in spec.params.get("fields") or []]
        strategy = str(spec.params.get("strategy", "hash"))
        if strategy not in {"hash", "tokenize", "redact", "partial"}:
            outcome = ActionOutcome(
                type=self.type,
                status=ActionStatus.FAILED,
                params={"fields": fields, "strategy": strategy},
                detail=f"неизвестная стратегия маскирования {strategy!r}",
            )
            self._record_metric(context, outcome)
            return outcome

        masked: list[str] = []
        for field_path in fields:
            for target in list(iter_targets(document, field_path)):
                if not isinstance(target.value, str) or not target.value:
                    continue
                target.set(mask_value(target.value, strategy, context.tokenize_secret))
                masked.append(field_path)
        outcome = ActionOutcome(
            type=self.type,
            status=ActionStatus.EXECUTED if masked else ActionStatus.SKIPPED,
            params={
                "fields": fields,
                "strategy": strategy,
                "masked": sorted(set(masked)),
            },
            detail=(
                f"замаскировано значений: {len(masked)} ({strategy})"
                if masked else "поля для маскирования не найдены в событии"
            ),
        )
        self._record_metric(context, outcome)
        return outcome


class TagExecutor(ActionExecutor):
    """Добавление тега к событию (используется SIEM при корреляции)."""

    type = ActionType.TAG

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        value = str(spec.params.get("value", "")).strip()
        tags = document.setdefault("tags", [])
        if not isinstance(tags, list):
            tags = list(tags or [])
            document["tags"] = tags
        if value and value not in tags:
            tags.append(value)
            outcome = ActionOutcome(
                type=self.type,
                status=ActionStatus.EXECUTED,
                params={"value": value},
                detail=f"добавлен тег {value}",
            )
        else:
            outcome = ActionOutcome(
                type=self.type,
                status=ActionStatus.SKIPPED,
                params={"value": value},
                detail="тег уже присутствует или не задан",
            )
        self._record_metric(context, outcome)
        return outcome


class AlertExecutor(ActionExecutor):
    """Алертинг: запись решения в журнал аудита и (опционально) уведомление по вебхуку."""

    type = ActionType.ALERT

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        severity = str(spec.params.get("severity", "medium"))
        message = str(spec.params.get("message", "сработало правило политики"))
        channel = str(spec.params.get("channel", "siem"))
        record = {
            "kind": "alert",
            "channel": channel,
            "severity": severity,
            "rule_id": context.rule_id,
            "event_id": context.event_id or document.get("event_id"),
            "message": message,
            "data_sensitivity": document.get("data_sensitivity"),
            "risk_score": document.get("risk_score"),
            "mode": context.mode,
        }
        if context.audit is not None:
            context.audit.write(record)

        detail = f"алерт зафиксирован в журнале аудита (канал {channel}, уровень {severity})"
        status = ActionStatus.EXECUTED
        url = spec.params.get("webhook_url") or context.webhook_url
        if url:
            delivered, note = _post_webhook(url, record, context.timeout_seconds, spec.params.get("headers"))
            detail += f"; вебхук: {note}"
            status = ActionStatus.EXECUTED if delivered else ActionStatus.FAILED
        outcome = ActionOutcome(
            type=self.type,
            status=status,
            params={"severity": severity, "channel": channel, "message": message},
            detail=detail,
        )
        self._record_metric(context, outcome)
        return outcome


class NotifyExecutor(ActionExecutor):
    """Уведомление внешней системы (SOAR, почта, мессенджер) — требует настроенного вебхука."""

    type = ActionType.NOTIFY

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        url = spec.params.get("webhook_url") or context.webhook_url
        if not url:
            outcome = ActionOutcome(
                type=self.type,
                status=ActionStatus.SKIPPED,
                params={"url": None},
                detail="не задан адрес вебхука (policy.webhook_url / POLICY_WEBHOOK_URL)",
            )
            self._record_metric(context, outcome)
            return outcome
        payload = {
            "kind": "notification",
            "rule_id": context.rule_id,
            "event_id": context.event_id or document.get("event_id"),
            "message": str(spec.params.get("message", "уведомление сервиса обогащения")),
            "severity": str(spec.params.get("severity", "medium")),
            "data_sensitivity": document.get("data_sensitivity"),
            "risk_score": document.get("risk_score"),
        }
        delivered, note = _post_webhook(url, payload, context.timeout_seconds, spec.params.get("headers"))
        if context.audit is not None:
            context.audit.write({**payload, "channel": "webhook", "delivered": delivered})
        outcome = ActionOutcome(
            type=self.type,
            status=ActionStatus.EXECUTED if delivered else ActionStatus.FAILED,
            params={"url": url},
            detail=note,
        )
        self._record_metric(context, outcome)
        return outcome


class BlockExecutorAction(ActionExecutor):
    """Блокировка процесса/файла/пользователя/адреса через выбранный исполнитель."""

    type = ActionType.BLOCK

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        target = str(spec.params.get("target", "process"))
        reason = str(spec.params.get("reason", f"правило {context.rule_id}"))
        requested_mode = str(spec.params.get("mode", context.mode))
        effective_mode = "live" if requested_mode == "live" and context.mode == "live" else "dry_run"
        blocker = context.blocker or DryRunBlocker()
        if effective_mode != "live":
            blocker = DryRunBlocker()
        result = blocker.block(target, reason, document)
        outcome = ActionOutcome(
            type=self.type,
            status=result.status,
            params={"target": target, "mode": effective_mode, "executor": blocker.name, **result.payload},
            detail=result.detail,
        )
        if context.audit is not None:
            context.audit.write(
                {
                    "kind": "block",
                    "rule_id": context.rule_id,
                    "event_id": context.event_id or document.get("event_id"),
                    "target": target,
                    "mode": effective_mode,
                    "executor": blocker.name,
                    "status": result.status.value,
                    "detail": result.detail,
                }
            )
        self._record_metric(context, outcome)
        return outcome


class QuarantineExecutor(ActionExecutor):
    """Карантин файла — точка расширения под конкретную EDR-систему."""

    type = ActionType.QUARANTINE

    def execute(self, spec: ActionSpec, document: dict[str, Any], context: ActionContext) -> ActionOutcome:
        file_path = document.get("file", {}).get("path") if isinstance(document.get("file"), Mapping) else None
        outcome = ActionOutcome(
            type=self.type,
            status=ActionStatus.SKIPPED,
            params={"file": file_path, "target": spec.params.get("target")},
            detail=(
                "карантин файла не выполнен: требуется интеграция с EDR/антивирусом "
                "(см. docs/07-политики-и-действия.md)"
            ),
        )
        if context.audit is not None:
            context.audit.write(
                {
                    "kind": "quarantine_request",
                    "rule_id": context.rule_id,
                    "event_id": context.event_id or document.get("event_id"),
                    "file": file_path,
                    "status": outcome.status.value,
                }
            )
        self._record_metric(context, outcome)
        return outcome


class ActionFactory:
    """Реестр исполнителей действий."""

    def __init__(self, executors: Sequence[ActionExecutor] | None = None) -> None:
        self._executors: dict[ActionType, ActionExecutor] = {}
        for executor in executors or (
            MaskFieldExecutor(), TagExecutor(), AlertExecutor(), NotifyExecutor(),
            BlockExecutorAction(), QuarantineExecutor(),
        ):
            self.register(executor)

    def register(self, executor: ActionExecutor) -> None:
        self._executors[executor.type] = executor

    def get(self, action_type: ActionType) -> ActionExecutor | None:
        return self._executors.get(action_type)

    def supported(self) -> list[str]:
        return sorted(t.value for t in self._executors)

    def execute_all(
        self,
        specs: Sequence[ActionSpec],
        document: dict[str, Any],
        context: ActionContext,
    ) -> tuple[list[ActionOutcome], list[str]]:
        """Выполнить набор действий. Возвращает результаты и список замаскированных полей."""
        outcomes: list[ActionOutcome] = []
        masked_fields: list[str] = []
        for spec in specs:
            executor = self.get(spec.type)
            if executor is None:
                outcomes.append(
                    ActionOutcome(
                        type=spec.type,
                        status=ActionStatus.SKIPPED,
                        params=dict(spec.params),
                        detail=f"исполнитель для действия {spec.type.value!r} не зарегистрирован",
                    )
                )
                continue
            try:
                outcome = executor.execute(spec, document, context)
            except Exception as exc:  # noqa: BLE001 - сбой действия не должен ронять конвейер
                logger.error("Ошибка выполнения действия политики",
                             extra={"action": spec.type.value, "rule_id": context.rule_id, "reason": str(exc)})
                outcome = ActionOutcome(
                    type=spec.type,
                    status=ActionStatus.FAILED,
                    params=dict(spec.params),
                    detail=f"ошибка выполнения: {exc}",
                )
            outcomes.append(outcome)
            masked_fields.extend(outcome.params.get("masked", []) or [])
        return outcomes, masked_fields


def _post_webhook(
    url: str,
    payload: Mapping[str, Any],
    timeout: float = 5.0,
    headers: Mapping[str, str] | None = None,
) -> tuple[bool, str]:
    """Отправить уведомление по HTTP. Возвращает (успех, пояснение)."""
    try:
        import httpx
    except ImportError:
        logger.warning("Вебхук не отправлен: модуль httpx не установлен")
        return False, "модуль httpx не установлен (pip install 'siem-enricher[http]')"
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=dict(payload), headers=dict(headers or {}))
        if response.status_code >= 400:
            return False, f"код ответа {response.status_code}"
        return True, f"уведомление доставлено ({response.status_code})"
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка отправки вебхука", extra={"url": url, "reason": str(exc)})
        return False, f"ошибка отправки: {exc}"


DEFAULT_FACTORY = ActionFactory()

__all__ = [
    "ActionContext",
    "ActionExecutor",
    "ActionFactory",
    "AlertExecutor",
    "BlockExecutorAction",
    "DEFAULT_FACTORY",
    "MaskFieldExecutor",
    "NotifyExecutor",
    "QuarantineExecutor",
    "TagExecutor",
    "mask_value",
]

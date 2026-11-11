"""Исполнители блокирующих воздействий."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from siem_enricher.logging_setup import get_logger
from siem_enricher.models.enums import ActionStatus
from siem_enricher.policy.fields import get_first

logger = get_logger("policy.blockers")


@dataclass(slots=True)
class BlockResult:
    """Результат попытки блокировки."""

    status: ActionStatus
    detail: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "detail": self.detail, "payload": self.payload}


class BlockExecutor(ABC):
    """Интерфейс исполнителя блокировок."""

    name = "abstract"

    @abstractmethod
    def block(self, target: str, reason: str, document: Mapping[str, Any]) -> BlockResult:
        """Заблокировать объект ``target`` (process|file|user|host|ip|endpoint)."""

    def describe(self) -> dict[str, str]:
        return {"executor": self.name}


class DryRunBlocker(BlockExecutor):
    """Режим имитации: блокировка фиксируется, но не выполняется."""

    name = "dry_run"

    def block(self, target: str, reason: str, document: Mapping[str, Any]) -> BlockResult:
        return BlockResult(
            status=ActionStatus.SIMULATED,
            detail=(
                f"режим dry_run: блокировка объекта «{target}» не выполнялась, "
                f"решение зафиксировано в журнале аудита ({reason})"
            ),
            payload={"target": target, "event_id": document.get("event_id")},
        )


class WebhookBlocker(BlockExecutor):
    """Передача команды блокировки во внешнюю систему (SOAR/EDR) по HTTP."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0, headers: Mapping[str, str] | None = None) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})

    def block(self, target: str, reason: str, document: Mapping[str, Any]) -> BlockResult:
        payload = {
            "action": "block",
            "target": target,
            "reason": reason,
            "event_id": document.get("event_id"),
            "data_sensitivity": document.get("data_sensitivity"),
            "risk_score": document.get("risk_score"),
            "policy_rule_ids": document.get("policy_rule_ids"),
        }
        try:
            import httpx
        except ImportError:
            return BlockResult(
                status=ActionStatus.SKIPPED,
                detail="модуль httpx не установлен: pip install 'siem-enricher[http]'",
                payload=payload,
            )
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.url, json=payload, headers=self.headers)
            if response.status_code >= 400:
                return BlockResult(
                    status=ActionStatus.FAILED,
                    detail=f"вебхук блокировки вернул код {response.status_code}",
                    payload=payload,
                )
            return BlockResult(
                status=ActionStatus.EXECUTED,
                detail=f"команда блокировки передана по адресу {self.url}",
                payload=payload,
            )
        except Exception as exc:  # noqa: BLE001 - сетевая ошибка фиксируется как FAILED
            logger.error("Ошибка вызова вебхука блокировки", extra={"url": self.url, "reason": str(exc)})
            return BlockResult(status=ActionStatus.FAILED, detail=f"ошибка вебхука: {exc}", payload=payload)


class WazuhActiveResponseBlocker(BlockExecutor):
    """Блокировка через Wazuh API (Active Response)."""

    name = "wazuh_active_response"

    def __init__(
        self,
        api_url: str,
        username: str = "",
        password: str = "",
        verify_tls: bool = False,
        timeout: float = 5.0,
        commands: Mapping[str, str] | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.commands = dict(commands or {"ip": "!firewall-drop", "endpoint": "!firewall-drop"})

    def block(self, target: str, reason: str, document: Mapping[str, Any]) -> BlockResult:
        command = self.commands.get(target)
        if command is None:
            return BlockResult(
                status=ActionStatus.SKIPPED,
                detail=(
                    f"Wazuh Active Response не поддерживает цель «{target}»: требуется интеграция "
                    "с EDR/SOAR (см. docs/07-политики-и-действия.md)"
                ),
                payload={"target": target},
            )
        arguments = self._arguments(target, document)
        if not arguments:
            return BlockResult(
                status=ActionStatus.SKIPPED,
                detail=f"в событии нет данных для блокировки цели «{target}»",
                payload={"target": target},
            )
        alert = self._build_alert(document, reason)
        try:
            import httpx
        except ImportError:
            return BlockResult(
                status=ActionStatus.SKIPPED,
                detail="модуль httpx не установлен: pip install 'siem-enricher[http]'",
            )
        url = f"{self.api_url}/active-response"
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify_tls) as client:
                response = client.put(
                    url,
                    json={"command": command, "arguments": arguments, "alert": alert},
                    auth=(self.username, self.password) if self.username else None,
                )
            if response.status_code >= 400:
                return BlockResult(
                    status=ActionStatus.FAILED,
                    detail=f"Wazuh API вернул код {response.status_code}: {response.text[:200]}",
                    payload={"command": command, "arguments": arguments},
                )
            return BlockResult(
                status=ActionStatus.EXECUTED,
                detail=f"Active Response {command} для {arguments} отправлен в Wazuh",
                payload={"command": command, "arguments": arguments},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка вызова Wazuh Active Response", extra={"url": url, "reason": str(exc)})
            return BlockResult(status=ActionStatus.FAILED, detail=f"ошибка Wazuh API: {exc}")

    @staticmethod
    def _arguments(target: str, document: Mapping[str, Any]) -> list[str]:
        if target in {"ip", "endpoint"}:
            ip = (
                get_first(document, "remote.ip")
                or get_first(document, "raw_event.data.win.eventdata.destinationIp")
                or get_first(document, "raw_event.data.srcip")
            )
            return [str(ip)] if ip else []
        if target == "host":
            host = get_first(document, "host.name")
            return [str(host)] if host else []
        return []

    @staticmethod
    def _build_alert(document: Mapping[str, Any], reason: str) -> dict[str, Any]:
        """Минимальный алерт, требуемый Wazuh API для вызова Active Response."""
        return {
            "id": document.get("event_id"),
            "rule": {
                "id": (get_first(document, "policy_rule_ids") or ["siem-enricher"])[0]
                if isinstance(get_first(document, "policy_rule_ids"), list)
                else "siem-enricher",
                "description": reason,
                "level": 12,
            },
            "agent": {"name": get_first(document, "host.name") or "unknown"},
            "data": {
                "data_sensitivity": document.get("data_sensitivity"),
                "risk_score": document.get("risk_score"),
                "policy_decision": document.get("policy_decision"),
            },
        }


def build_blocker(
    mode: str,
    webhook_url: str = "",
    wazuh_api_url: str = "",
    wazuh_user: str = "",
    wazuh_password: str = "",
) -> BlockExecutor:
    """Выбрать исполнителя блокировок по конфигурации."""
    if mode != "live":
        return DryRunBlocker()
    if wazuh_api_url:
        return WazuhActiveResponseBlocker(wazuh_api_url, wazuh_user, wazuh_password)
    if webhook_url:
        return WebhookBlocker(webhook_url)
    logger.warning(
        "policy.mode=live, но не настроены Wazuh API или вебхук блокировки: "
        "используется режим имитации"
    )
    return DryRunBlocker()

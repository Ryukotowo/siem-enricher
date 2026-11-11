"""Вебхук-приёмник: возврат обогащённых событий в SIEM/SOAR по HTTP."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from siem_enricher.connectors.base import SinkConnector, register_sink
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import ServiceMetrics

logger = get_logger("connectors.webhook")


@register_sink("webhook")
class WebhookSink(SinkConnector):
    """Отправка обогащённых событий в HTTP-приёмник (REST API SIEM, SOAR, шина обмена)."""

    def __init__(
        self,
        options: Mapping[str, Any] | None = None,
        metrics: ServiceMetrics | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(options, metrics, name or "webhook")
        self.url = str(self._option("url", ""))
        if not self.url:
            raise ValueError("Приёмник webhook требует параметр options.url")
        self.timeout = float(self._option("timeout_seconds", 5.0))
        self.headers = dict(self._option("headers") or {})
        self.batch_size = max(1, int(self._option("batch_size", 1)))
        self.max_retries = max(0, int(self._option("max_retries", 3)))
        self.backoff = float(self._option("retry_backoff_seconds", 0.5))
        self.verify_tls = bool(self._option("verify_tls", True))
        self._client: Any = None
        self._buffer: list[dict[str, Any]] = []

    async def start(self) -> None:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "Для приёмника webhook требуется httpx: pip install 'siem-enricher[http]'"
            ) from exc
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls, headers=self.headers)
        self._started = True

    async def send(self, document: dict[str, Any]) -> bool:
        self._buffer.append(document)
        if len(self._buffer) < self.batch_size:
            return True
        return await self.flush()

    async def flush(self) -> bool:
        """Отправить буфер. Возвращает признак успеха."""
        if not self._buffer:
            return True
        if self._client is None:
            await self.start()
        payload: Any = self._buffer[0] if len(self._buffer) == 1 else list(self._buffer)
        count = len(self._buffer)
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.post(self.url, json=payload)
                if response.status_code < 400:
                    self._buffer.clear()
                    if self.metrics is not None:
                        self.metrics.sink_sent.inc({"sink": self.name, "status": "ok"}, value=count)
                    return True
                detail = f"код ответа {response.status_code}"
            except Exception as exc:  # noqa: BLE001 - сетевые ошибки повторяем
                detail = str(exc)
            if attempt < self.max_retries:
                await asyncio.sleep(self.backoff * (2 ** attempt))
        logger.error("Не удалось отправить события в вебхук",
                     extra={"url": self.url, "count": count, "reason": detail})
        if self.metrics is not None:
            self.metrics.sink_sent.inc({"sink": self.name, "status": "error"}, value=count)
        self._buffer.clear()
        return False

    async def stop(self) -> None:
        await self.flush()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._started = False

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"url": self.url, "batch_size": self.batch_size})
        return info

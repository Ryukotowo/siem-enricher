"""HTTP-сервис обогащения событий (FastAPI)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from siem_enricher.config import AppConfig
from siem_enricher.enricher import EnrichmentPipeline
from siem_enricher.logging_setup import get_logger, setup_logging
from siem_enricher.metrics import ServiceMetrics, service_metrics
from siem_enricher.service.runtime import EnrichmentRuntime
from siem_enricher.version import VERSION

logger = get_logger("service.app")


def _install_api_key_guard(app: Any, config: AppConfig) -> None:
    """Требовать X-API-Key для изменяющих запросов, если ключ задан.

    Чтение панели, метрики и проверки состояния остаются открытыми, чтобы
    мониторинг и просмотр не зависели от ключа.
    """
    expected = str(getattr(config.http, "api_key", "") or "")
    if not expected:
        logger.warning("HTTP API-ключ не задан: изменяющие запросы открыты")
        return

    import hmac

    from fastapi.responses import JSONResponse

    open_paths = {"/healthz", "/readyz", "/ui", "/ui/stream", "/metrics"}
    open_prefixes = ("/ui/events", "/ui/audit", "/ui/labels", "/ui/state", "/ui/rules/versions")

    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        method = request.method.upper()
        path = request.url.path
        protected = method in {"POST", "PUT", "PATCH", "DELETE"}
        if protected and path not in open_paths and not path.startswith(open_prefixes):
            provided = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(provided, expected):
                return JSONResponse({"detail": "требуется заголовок X-API-Key"}, status_code=401)
        return await call_next(request)

def _noop() -> None:
    """Заглушка, чтобы сохранить структуру модуля."""



def create_app(
    config: AppConfig,
    pipeline: EnrichmentPipeline | None = None,
    runtime: EnrichmentRuntime | None = None,
    metrics: ServiceMetrics | None = None,
    run_pipeline: bool = False,
) -> Any:
    """Создать приложение FastAPI с настроенным конвейером обогащения."""
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise RuntimeError(
            "Для запуска HTTP-сервиса требуется FastAPI: pip install 'siem-enricher[service]'"
        ) from exc

    from siem_enricher.service import routes

    metrics = metrics or service_metrics()
    pipeline = pipeline or EnrichmentPipeline.from_config(config, metrics=metrics)
    runtime = runtime or EnrichmentRuntime(config, pipeline=pipeline, metrics=metrics)

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        app.state.started_at = time.time()
        task: asyncio.Task[Any] | None = None
        if app.state.run_pipeline:
            task = asyncio.create_task(runtime.run(), name="siem-enricher-pipeline")
            logger.info("Фоновый конвейер обогащения запущен вместе с сервисом")
        try:
            yield
        finally:
            if task is not None:
                runtime.request_stop()
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            pipeline.close()
            logger.info("Сервис обогащения остановлен", extra=runtime.stats())

    app = FastAPI(
        title="SIEM Enrichment Service",
        version=VERSION,
        summary="Сервис обогащения событий SIEM: конфиденциальность, provenance, риск, политики",
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.metrics = metrics
    app.state.pipeline = pipeline
    app.state.runtime = runtime
    app.state.run_pipeline = run_pipeline
    app.state.started_at = time.time()

    from siem_enricher.service.panel import EventBuffer, register_panel

    panel_buffer = EventBuffer(500)
    if register_panel(app, panel_buffer):
        pipeline.add_observer(panel_buffer.add)
        logger.info("Панель аналитика доступна по адресу /ui (обновляется по мере потока)")
    _install_api_key_guard(app, config)
    app.include_router(routes.router)
    logger.info(
        "HTTP-сервис обогащения создан",
        extra={"config": config.describe(), "run_pipeline": run_pipeline},
    )
    return app


def serve(
    config: AppConfig,
    host: str | None = None,
    port: int | None = None,
    run_pipeline: bool = False,
    log_level: str | None = None,
) -> None:
    """Запустить сервис через uvicorn (используется CLI)."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Для запуска HTTP-сервиса требуется uvicorn: pip install 'siem-enricher[service]'"
        ) from exc

    setup_logging(
        level=log_level or config.service.log_level,
        fmt=config.service.log_format,
        service=config.service.name,
        instance=config.service.instance_id,
    )
    app = create_app(config, run_pipeline=run_pipeline)
    uvicorn.run(
        app,
        host=host or config.http.host,
        port=port or config.http.port,
        log_config=None,
    )


__all__ = ["create_app", "serve"]

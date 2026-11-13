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
    """Разграничить доступ: пишущий ключ меняет состояние, читающий только смотрит.

    Ключ принимается заголовком X-API-Key или cookie siem_key (её ставит страница
    панели при переходе по ссылке с параметром ?key=). Проверки состояния и метрики
    остаются открытыми для мониторинга.
    """
    if not (getattr(config.http, "api_key", "") or getattr(config.http, "read_key", "")):
        logger.warning("HTTP-ключи не заданы: доступ открыт")

    import hmac

    from fastapi.responses import JSONResponse

    public_paths = {"/healthz", "/readyz", "/metrics", "/ui", "/favicon.ico"}
    write_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def given(request: Any) -> str:
        return (request.headers.get("X-API-Key")
                or request.cookies.get("siem_key")
                or request.query_params.get("key")
                or "")

    @app.middleware("http")
    async def api_key_guard(request: Any, call_next: Any) -> Any:
        settings = getattr(request.app.state, "config", config).http
        write_key = str(getattr(settings, "api_key", "") or "")
        read_key = str(getattr(settings, "read_key", "") or "")
        path = request.url.path
        if not write_key and not read_key:
            return await call_next(request)
        if path in public_paths:
            response = await call_next(request)
            supplied = request.query_params.get("key")
            if path == "/ui" and supplied:
                response.set_cookie("siem_key", supplied, httponly=True, samesite="strict")
            return response

        token = given(request)
        if request.method.upper() in write_methods:
            ok = bool(write_key) and hmac.compare_digest(token, write_key)
            detail = "требуется пишущий ключ (X-API-Key)"
        else:
            if not read_key:
                ok = True  # читающий ключ не задан — чтение открыто
            else:
                allowed = [key for key in (read_key, write_key) if key]
                ok = any(hmac.compare_digest(token, key) for key in allowed)
            detail = "требуется читающий ключ (X-API-Key)"
        if not ok:
            return JSONResponse({"detail": detail}, status_code=401)
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

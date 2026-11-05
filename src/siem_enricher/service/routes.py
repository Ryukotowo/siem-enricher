"""HTTP-маршруты сервиса обогащения."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Body, Query, Request, Response

from siem_enricher.audit import AuditLogger
from siem_enricher.logging_setup import get_logger
from siem_enricher.metrics import render_prometheus
from siem_enricher.service.runtime import EnrichmentRuntime
from siem_enricher.version import ENRICHMENT_SCHEMA_VERSION, VERSION

logger = get_logger("service.routes")

router = APIRouter()


def _runtime(request: Request) -> EnrichmentRuntime:
    return request.app.state.runtime


@router.get("/healthz", summary="Проверка живости")
async def healthz(request: Request) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": VERSION,
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "instance_id": request.app.state.config.service.instance_id,
        "uptime_seconds": round(time.time() - request.app.state.started_at, 3),
    }


@router.get("/readyz", summary="Проверка готовности")
async def readyz(request: Request) -> Response:
    runtime = _runtime(request)
    pipeline = runtime.pipeline
    checks = {
        "pipeline": pipeline is not None,
        "provenance_store": pipeline.store.ping() if pipeline else False,
        "policies_loaded": bool(pipeline.policy_engine.rules) if pipeline and pipeline.policy_engine else False,
        "classifier": pipeline.classifier.describe() if pipeline else {},
    }
    ready = all(value for key, value in checks.items() if key != "classifier")
    payload = {"status": "ready" if ready else "not_ready", "checks": checks}
    return Response(
        content=json.dumps(payload, ensure_ascii=False, default=str),
        media_type="application/json",
        status_code=200 if ready else 503,
    )


@router.get("/metrics", summary="Метрики Prometheus")
async def metrics() -> Response:
    return Response(content=render_prometheus(), media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/v1/version", summary="Версия и состав конвейера")
async def version(request: Request) -> dict[str, Any]:
    runtime = _runtime(request)
    return {
        "service": "siem-enricher",
        "version": VERSION,
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "pipeline": runtime.pipeline.describe(),
        "runtime": runtime.stats(),
    }


@router.post("/v1/enrich", summary="Обогатить одно событие")
async def enrich(
    request: Request,
    payload: dict[str, Any] = Body(..., description="«Сырое» событие SIEM"),
    source: str = Query("api", description="Идентификатор источника события"),
    apply_policies: bool = Query(True, description="Применять политики"),
) -> dict[str, Any]:
    runtime = _runtime(request)
    _, _, document = runtime.pipeline.enrich_document(source, payload, apply_policies=apply_policies)
    buffer = getattr(request.app.state, "panel_buffer", None)
    if buffer is not None:
        buffer.add(document)
    return document


@router.post("/v1/enrich/batch", summary="Обогатить пакет событий")
async def enrich_batch(
    request: Request,
    payload: dict[str, Any] = Body(..., description="{events: [...]} либо список событий"),
    source: str = Query("api"),
    apply_policies: bool = Query(True),
) -> dict[str, Any]:
    runtime = _runtime(request)
    events = payload.get("events") if isinstance(payload, dict) else payload
    if not isinstance(events, list):
        return {"error": "ожидался объект {events: [...]} или список событий", "results": []}
    enriched = await runtime.enrich_documents(events, source=source, apply_policies=apply_policies)
    documents = [item.siem_document() for item in enriched]
    buffer = getattr(request.app.state, "panel_buffer", None)
    if buffer is not None:
        buffer.extend(documents)
    return {
        "results": documents,
        "summary": runtime.pipeline.summarize(enriched),
    }


@router.post("/v1/classify", summary="Классифицировать конфиденциальность путей")
async def classify(
    request: Request,
    payload: dict[str, Any] = Body(..., description="{path: \"...\"} или {paths: [...]}"),
) -> dict[str, Any]:
    runtime = _runtime(request)
    paths: list[str] = []
    if isinstance(payload.get("paths"), list):
        paths = [str(p) for p in payload["paths"]]
    elif payload.get("path"):
        paths = [str(payload["path"])]
    if not paths:
        return {"error": "не заданы пути (path или paths)", "results": []}
    assessments = runtime.pipeline.classifier.predict_many(paths)
    return {
        "model": runtime.pipeline.classifier.describe(),
        "results": [assessment.to_dict() for assessment in assessments],
    }


@router.get("/v1/policies", summary="Список правил политик")
async def list_policies(request: Request) -> dict[str, Any]:
    runtime = _runtime(request)
    engine = runtime.pipeline.policy_engine
    return {
        "mode": engine.mode if engine else None,
        "rules_count": len(engine.rules) if engine else 0,
        "rules": runtime.pipeline.policy_summary(),
    }


@router.post("/v1/policies/reload", summary="Перечитать правила политик")
async def reload_policies(request: Request) -> dict[str, Any]:
    runtime = _runtime(request)
    count = runtime.pipeline.reload_policies()
    logger.info("Правила политик перезагружены через API", extra={"count": count})
    return {"status": "reloaded", "rules_count": count}


@router.post("/v1/provenance/chain", summary="Цепочка происхождения файла")
async def provenance_chain(
    request: Request,
    payload: dict[str, Any] = Body(..., description="{path: \"...\"}"),
) -> dict[str, Any]:
    runtime = _runtime(request)
    path = str(payload.get("path") or "")
    if not path:
        return {"error": "не задан путь (path)", "chain": None}
    chain = runtime.pipeline.chain(path)
    return {"chain": chain.to_dict()}


@router.get("/v1/audit", summary="Последние записи журнала аудита")
async def audit_tail(
    request: Request,
    limit: int = Query(50, ge=1, le=1000),
) -> dict[str, Any]:
    """Отдать последние решения политик из журнала аудита (удобно для проверки в демонстрации)."""
    path = request.app.state.config.audit_log_path
    logger_reader = AuditLogger(path)
    records = logger_reader.read_all()
    return {"path": str(path), "total": len(records), "records": records[-limit:]}

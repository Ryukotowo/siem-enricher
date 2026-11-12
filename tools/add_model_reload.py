"""Порядок выбора модели и перезагрузка модели через панель."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "src" / "siem_enricher" / "ml" / "classifier.py"
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

# 1. для организации без реестра — универсальная модель, а не случайный свежий каталог
FALLBACK_OLD = '''    root = base
    if tenant and tenant != "default":'''
FALLBACK_NEW = '''    root = base
    if tenant and tenant != "default":
        universal = base / "sensitivity_transformer"
        scoped = base / tenant
        if not scoped.exists() and (universal / "config.json").exists():
            return universal.resolve()'''

# 2. перезагрузка модели в панели
MODEL_HELPER_ANCHOR = "def reload_rules(app: Any) -> dict[str, Any]:"
MODEL_HELPER = '''def reload_model(app: Any) -> dict[str, Any]:
    """Пересобрать классификатор с активной версией модели из реестра."""
    pipeline = _pipeline_of(app)
    config = getattr(app.state, "config", None)
    if pipeline is None or config is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    from siem_enricher.ml.classifier import build_classifier
    from siem_enricher.ml.registry import ModelRegistry

    fresh = build_classifier(config.ml, None, labels_path=config.labels_path)
    pipeline.classifier = fresh
    registry = ModelRegistry(current_tenant(config))
    active = registry.active() or {}
    _audit(app, {"kind": "model_reload", "key": "ml/artifact",
                 "from": "-", "to": active.get("id") or getattr(fresh, "model_version", "unknown")})
    return {
        "ok": True,
        "model_version": getattr(fresh, "model_version", "unknown"),
        "artifact": active.get("artifact"),
        "version": active.get("id"),
    }


def reload_rules(app: Any) -> dict[str, Any]:'''

ROUTE_ANCHOR = '    @app.post("/ui/rules/reload", include_in_schema=False)'
ROUTE = '''    @app.post("/ui/model/reload", include_in_schema=False)
    async def panel_model_reload(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        result = reload_model(request.app)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)

'''


def main() -> int:
    changed = 0

    classifier_text = CLASSIFIER.read_text(encoding="utf-8")
    if "universal = base" not in classifier_text:
        if FALLBACK_OLD not in classifier_text:
            print("!! не найден блок tenant")
            return 1
        classifier_text = classifier_text.replace(FALLBACK_OLD, FALLBACK_NEW, 1)
        CLASSIFIER.write_text(classifier_text, encoding="utf-8")
        ast.parse(classifier_text)
        changed += 1
        print("classifier: для организации без реестра — универсальная модель")

    panel_text = PANEL.read_text(encoding="utf-8")
    if "def reload_model" not in panel_text:
        panel_text = panel_text.replace(MODEL_HELPER_ANCHOR, MODEL_HELPER, 1)
        changed += 1
        print("панель: reload_model()")
    if "/ui/model/reload" not in panel_text:
        panel_text = panel_text.replace(ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR, 1)
        changed += 1
        print("панель: маршрут /ui/model/reload")
    PANEL.write_text(panel_text, encoding="utf-8")
    ast.parse(panel_text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

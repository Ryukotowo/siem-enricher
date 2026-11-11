"""Новые метрики: решения, кэш классификатора, метки, изменения настроек."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "src" / "siem_enricher" / "metrics.py"
PIPELINE = ROOT / "src" / "siem_enricher" / "enricher" / "pipeline.py"
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
ROUTES = ROOT / "src" / "siem_enricher" / "service" / "routes.py"

METRICS_ANCHOR = '''        self.queue_size = r.gauge(
            "siem_enricher_queue_size",
            "Текущий размер очереди ожидающих обработки событий",
        )'''
METRICS_NEW = METRICS_ANCHOR + '''
        self.decisions = r.counter(
            "siem_enricher_policy_decisions_total",
            "Решения политик по событиям",
            ("decision",),
        )
        self.config_changes = r.counter(
            "siem_enricher_config_changes_total",
            "Изменения настроек и правил через панель",
            ("key",),
        )
        self.analyst_labels = r.counter(
            "siem_enricher_analyst_labels_total",
            "Оценки аналитиков по событиям",
            ("label",),
        )
        self.cache_hits = r.gauge(
            "siem_enricher_classifier_cache_hits",
            "Попадания в кэш классификации",
        )
        self.cache_misses = r.gauge(
            "siem_enricher_classifier_cache_misses",
            "Промахи кэша классификации",
        )
        self.cache_entries = r.gauge(
            "siem_enricher_classifier_cache_entries",
            "Число записей в кэше классификации",
        )'''

PIPELINE_OLD = "            self.metrics.events_enriched.inc({\"status\": \"ok\"})"
PIPELINE_NEW = ("            self.metrics.events_enriched.inc({\"status\": \"ok\"})\n"
                "            self.metrics.decisions.inc({\"decision\": result.policy_decision.value})")

PANEL_AUDIT_OLD = '''    payload.setdefault("actor", getattr(app.state, "audit_actor", "panel"))'''
PANEL_AUDIT_NEW = '''    payload.setdefault("actor", getattr(app.state, "audit_actor", "panel"))
    try:
        from siem_enricher.metrics import service_metrics

        service_metrics().config_changes.inc(
            {"key": str(record.get("key") or record.get("rule") or "unknown")}
        )
    except Exception:  # noqa: BLE001
        pass'''

PANEL_LABEL_OLD = '''    with _labels_path().open("a", encoding="utf-8") as handle:'''
PANEL_LABEL_NEW = '''    try:
        from siem_enricher.metrics import service_metrics

        service_metrics().analyst_labels.inc({"label": label})
    except Exception:  # noqa: BLE001
        pass
    with _labels_path().open("a", encoding="utf-8") as handle:'''

ROUTES_OLD = "async def metrics() -> Response:"
ROUTES_NEW = '''async def metrics(request: Request) -> Response:'''

ROUTES_BODY_OLD = '''async def metrics(request: Request) -> Response:'''
ROUTES_SYNC = '''        pipeline = getattr(getattr(request.app.state, "runtime", None), "pipeline", None)
        classifier = getattr(pipeline, "classifier", None)
        if classifier is not None and hasattr(classifier, "hits"):
            metrics_obj = service_metrics()
            metrics_obj.cache_hits.set(float(classifier.hits))
            metrics_obj.cache_misses.set(float(classifier.misses))
            metrics_obj.cache_entries.set(float(len(getattr(classifier, "_cache", {}))))


'''


def patch(path: Path, old: str, new: str, label: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if new.strip() and new.split("\n")[0].strip() and new in text:
        print(f"  уже есть: {label}")
        return True
    if old not in text:
        print(f"  !! не найдено: {label}")
        return False
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  патч: {label}")
    return True


def main() -> int:
    patch(METRICS, METRICS_ANCHOR, METRICS_NEW, "метрики решений, кэша и меток")
    patch(PIPELINE, PIPELINE_OLD, PIPELINE_NEW, "счётчик решений в конвейере")
    patch(PANEL, PANEL_AUDIT_OLD, PANEL_AUDIT_NEW, "счётчик изменений настроек")
    patch(PANEL, PANEL_LABEL_OLD, PANEL_LABEL_NEW, "счётчик меток аналитика")
    patch(ROUTES, ROUTES_OLD, ROUTES_NEW, "metrics принимает request")
    text = ROUTES.read_text(encoding="utf-8")
    if "cache_hits.set" not in text:
        marker = "        return Response(render_prometheus(), media_type=\"text/plain; version=0.0.4\")"
        if marker in text:
            text = text.replace(marker, ROUTES_SYNC + marker, 1)
            ROUTES.write_text(text, encoding="utf-8")
            print("  патч: обновление датчиков кэша при скрапе")
    for path in (METRICS, PIPELINE, PANEL, ROUTES):
        ast.parse(path.read_text(encoding="utf-8"))
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Добавление новых метрик и синхронизации кэша при скрапе."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "src" / "siem_enricher" / "metrics.py"
ROUTES = ROOT / "src" / "siem_enricher" / "service" / "routes.py"

NEW_METRICS = '''
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

ROUTE_OLD = (
    '    return Response(content=render_prometheus(), '
    'media_type="text/plain; version=0.0.4; charset=utf-8")'
)
ROUTE_NEW = '''    from siem_enricher.metrics import service_metrics

    pipeline = getattr(getattr(request.app.state, "runtime", None), "pipeline", None)
    classifier = getattr(pipeline, "classifier", None)
    if classifier is not None and hasattr(classifier, "hits"):
        counters = service_metrics()
        counters.cache_hits.set(float(classifier.hits))
        counters.cache_misses.set(float(classifier.misses))
        counters.cache_entries.set(float(len(getattr(classifier, "_cache", {}))))
    return Response(content=render_prometheus(),
                    media_type="text/plain; version=0.0.4; charset=utf-8")'''


def main() -> int:
    text = METRICS.read_text(encoding="utf-8")
    if "siem_enricher_policy_decisions_total" not in text:
        match = re.search(r"(\n        self\.queue_size = r\.gauge\((?:[^()]|\([^()]*\))*?\n        \))", text)
        if not match:
            print("!! не найден блок queue_size")
            return 1
        text = text[:match.end(1)] + NEW_METRICS + text[match.end(1):]
        METRICS.write_text(text, encoding="utf-8")
        ast.parse(text)
        print("метрики добавлены")
    else:
        print("метрики уже есть")

    routes = ROUTES.read_text(encoding="utf-8")
    if "cache_hits.set" in routes:
        print("синхронизация кэша уже есть")
        return 0
    if ROUTE_OLD not in routes:
        print("!! не найдено тело /metrics")
        return 1
    routes = routes.replace(ROUTE_OLD, ROUTE_NEW, 1)
    ROUTES.write_text(routes, encoding="utf-8")
    ast.parse(routes)
    print("синхронизация кэша при скрапе добавлена")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

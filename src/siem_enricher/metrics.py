"""Метрики сервиса в формате Prometheus."""

from __future__ import annotations

import math
import threading
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

DEFAULT_BUCKETS: tuple[float, ...] = (
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

Labels = Mapping[str, object] | None
#: Один образец метрики: (суффикс имени, метки, значение)
Sample = tuple[str, dict[str, str], float]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(value: float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    as_float = float(value)
    if math.isinf(as_float):
        return "+Inf" if as_float > 0 else "-Inf"
    if as_float.is_integer() and abs(as_float) < 1e15:
        return str(int(as_float))
    return repr(as_float)


def _labels_str(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    pairs = [f'{name}="{_escape(str(value))}"' for name, value in sorted(labels.items())]
    return "{" + ",".join(pairs) + "}"


class Metric:
    """Базовый класс метрики."""

    kind = "untyped"

    def __init__(self, name: str, help_text: str = "", labelnames: Sequence[str] = ()) -> None:
        self.name = name
        self.help = help_text or name
        self.labelnames = tuple(labelnames)
        self._lock = threading.Lock()

    def _key(self, labels: Labels) -> tuple[tuple[str, str], ...]:
        data = labels or {}
        return tuple((n, str(data.get(n, ""))) for n in self.labelnames)

    @staticmethod
    def _labels_from_key(key: tuple[tuple[str, str], ...]) -> dict[str, str]:
        return dict(key)

    def samples(self) -> Iterable[Sample]:
        raise NotImplementedError

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]
        for suffix, labels, value in self.samples():
            lines.append(f"{self.name}{suffix}{_labels_str(labels)} {_fmt(value)}")
        return lines


class Counter(Metric):
    """Монотонно возрастающий счётчик."""

    kind = "counter"

    def __init__(self, name: str, help_text: str = "", labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help_text, labelnames)
        self._values: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)

    def inc(self, labels: Labels = None, value: float = 1.0) -> None:
        with self._lock:
            self._values[self._key(labels)] += value

    def value(self, labels: Labels = None) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def total(self) -> float:
        with self._lock:
            return sum(self._values.values())

    def samples(self) -> Iterable[Sample]:
        with self._lock:
            items = list(self._values.items())
        for key, value in items:
            yield "", self._labels_from_key(key), value


class Gauge(Metric):
    """Мгновенное значение."""

    kind = "gauge"

    def __init__(self, name: str, help_text: str = "", labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help_text, labelnames)
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def set(self, value: float, labels: Labels = None) -> None:
        with self._lock:
            self._values[self._key(labels)] = float(value)

    def inc(self, value: float = 1.0, labels: Labels = None) -> None:
        with self._lock:
            key = self._key(labels)
            self._values[key] = self._values.get(key, 0.0) + value

    def dec(self, value: float = 1.0, labels: Labels = None) -> None:
        self.inc(-value, labels)

    def value(self, labels: Labels = None) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def samples(self) -> Iterable[Sample]:
        with self._lock:
            items = list(self._values.items())
        for key, value in items:
            yield "", self._labels_from_key(key), value


class Histogram(Metric):
    """Гистограмма распределения значений."""

    kind = "histogram"

    def __init__(
        self,
        name: str,
        help_text: str = "",
        labelnames: Sequence[str] = (),
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ) -> None:
        super().__init__(name, help_text, labelnames)
        self.buckets = tuple(sorted(buckets))
        # Для каждого набора меток: счётчики по «корзинам» + отдельная ячейка +Inf
        self._counts: dict[tuple[tuple[str, str], ...], list[int]] = defaultdict(
            lambda: [0] * (len(self.buckets) + 1)
        )
        self._sums: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)
        self._totals: dict[tuple[tuple[str, str], ...], int] = defaultdict(int)

    def observe(self, value: float, labels: Labels = None) -> None:
        with self._lock:
            key = self._key(labels)
            index = len(self.buckets)
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    index = i
                    break
            self._counts[key][index] += 1
            self._sums[key] += float(value)
            self._totals[key] += 1

    def count(self, labels: Labels = None) -> int:
        with self._lock:
            return self._totals.get(self._key(labels), 0)

    def samples(self) -> Iterable[Sample]:
        with self._lock:
            keys = list(self._counts.keys())
            counts = {key: list(self._counts[key]) for key in keys}
            sums = dict(self._sums)
            totals = dict(self._totals)
        for key in keys:
            base = self._labels_from_key(key)
            cumulative = 0
            for i, bound in enumerate(self.buckets):
                cumulative += counts[key][i]
                yield "_bucket", {**base, "le": _fmt(bound)}, float(cumulative)
            cumulative += counts[key][len(self.buckets)]
            yield "_bucket", {**base, "le": "+Inf"}, float(cumulative)
            yield "_sum", base, sums[key]
            yield "_count", base, float(totals[key])


class MetricsRegistry:
    """Реестр метрик с экспортом в текстовый формат Prometheus."""

    def __init__(self) -> None:
        self._metrics: dict[str, Metric] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, help_text: str = "", labelnames: Sequence[str] = ()) -> Counter:
        metric = self._get(name, Counter, help_text, labelnames)
        assert isinstance(metric, Counter)
        return metric

    def gauge(self, name: str, help_text: str = "", labelnames: Sequence[str] = ()) -> Gauge:
        metric = self._get(name, Gauge, help_text, labelnames)
        assert isinstance(metric, Gauge)
        return metric

    def histogram(
        self,
        name: str,
        help_text: str = "",
        labelnames: Sequence[str] = (),
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ) -> Histogram:
        with self._lock:
            metric = self._metrics.get(name)
            if metric is None:
                metric = Histogram(name, help_text, labelnames, buckets)
                self._metrics[name] = metric
            if not isinstance(metric, Histogram):
                raise TypeError(f"Метрика {name} уже зарегистрирована как {type(metric).__name__}")
        return metric

    def _get(self, name: str, cls: type[Metric], help_text: str, labelnames: Sequence[str]) -> Metric:
        with self._lock:
            metric = self._metrics.get(name)
            if metric is None:
                metric = cls(name, help_text, labelnames)
                self._metrics[name] = metric
            if not isinstance(metric, cls):
                raise TypeError(f"Метрика {name} уже зарегистрирована как {type(metric).__name__}")
        return metric

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._metrics)

    def render(self) -> str:
        with self._lock:
            metrics = list(self._metrics.values())
        lines: list[str] = []
        for metric in metrics:
            lines.extend(metric.render())
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._metrics.clear()


class ServiceMetrics:
    """Набор метрик предметной области сервиса обогащения."""

    def __init__(self, registry: MetricsRegistry | None = None) -> None:
        self.registry = registry or REGISTRY
        r = self.registry
        self.events_consumed = r.counter(
            "siem_enricher_events_consumed_total",
            "Число событий, полученных от источника",
            ("source", "status"),
        )
        self.events_enriched = r.counter(
            "siem_enricher_events_enriched_total",
            "Число обогащённых событий",
            ("status",),
        )
        self.enrichment_duration = r.histogram(
            "siem_enricher_enrichment_duration_seconds",
            "Длительность обогащения одного события",
        )
        self.classified = r.counter(
            "siem_enricher_sensitivity_classified_total",
            "Число классифицированных объектов по классам конфиденциальности",
            ("level", "method"),
        )
        self.ml_fallback = r.counter(
            "siem_enricher_ml_fallback_total",
            "Число случаев использования эвристического классификатора вместо ML-модели",
            ("reason",),
        )
        self.risk_score = r.histogram(
            "siem_enricher_risk_score",
            "Распределение итоговой оценки риска",
            (),
            buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
        )
        self.risk_severity = r.counter(
            "siem_enricher_risk_severity_total",
            "Число событий по уровням риска",
            ("severity",),
        )
        self.provenance_depth = r.histogram(
            "siem_enricher_provenance_chain_depth",
            "Глубина цепочки происхождения файла",
            (),
            buckets=(1, 2, 3, 4, 6, 8, 12, 16, 32),
        )
        self.policy_triggered = r.counter(
            "siem_enricher_policy_triggered_total",
            "Число срабатываний правил политик",
            ("rule_id", "decision", "severity"),
        )
        self.policy_actions = r.counter(
            "siem_enricher_policy_actions_total",
            "Число выполненных действий политик",
            ("type", "status"),
        )
        self.sink_sent = r.counter(
            "siem_enricher_sink_sent_total",
            "Число документов, отправленных в приёмник",
            ("sink", "status"),
        )
        self.source_errors = r.counter(
            "siem_enricher_source_errors_total",
            "Число ошибок чтения источника",
            ("source",),
        )
        self.uptime_seconds = r.gauge(
            "siem_enricher_uptime_seconds",
            "Время работы сервиса в секундах",
        )
        self.queue_size = r.gauge(
            "siem_enricher_queue_size",
            "Текущий размер очереди необработанных событий",
        )


REGISTRY = MetricsRegistry()
_SERVICE_METRICS: ServiceMetrics | None = None
_LOCK = threading.Lock()


def service_metrics() -> ServiceMetrics:
    """Вернуть singleton-набор метрик сервиса."""
    global _SERVICE_METRICS
    with _LOCK:
        if _SERVICE_METRICS is None:
            _SERVICE_METRICS = ServiceMetrics(REGISTRY)
        return _SERVICE_METRICS


def render_prometheus() -> str:
    """Текстовое представление всех метрик для эндпоинта ``/metrics``."""
    return REGISTRY.render()


def reset_metrics() -> None:
    """Сбросить метрики (используется в тестах)."""
    global _SERVICE_METRICS
    with _LOCK:
        REGISTRY.reset()
        _SERVICE_METRICS = None


def quantile(values: Sequence[float], q: float) -> float:
    """Перцентиль по выборке — вспомогательная функция для отчётов по замерам."""
    if not values:
        return math.nan
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)

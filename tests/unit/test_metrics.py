"""Тесты метрик Prometheus."""

from __future__ import annotations

import unittest

from siem_enricher.metrics import MetricsRegistry, ServiceMetrics, render_prometheus


class ServiceMetricsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = MetricsRegistry()
        self.metrics = ServiceMetrics(self.registry)

    def render(self) -> str:
        return self.registry.render()

    def test_decisions_counter_groups_by_decision(self) -> None:
        self.metrics.decisions.inc({"decision": "block"})
        self.metrics.decisions.inc({"decision": "block"})
        self.metrics.decisions.inc({"decision": "allow"})
        text = self.render()
        self.assertIn('siem_enricher_policy_decisions_total{decision="block"} 2', text)
        self.assertIn('siem_enricher_policy_decisions_total{decision="allow"} 1', text)

    def test_cache_gauges_are_rendered(self) -> None:
        self.metrics.cache_hits.set(67)
        self.metrics.cache_misses.set(24)
        self.metrics.cache_entries.set(24)
        text = self.render()
        self.assertIn("siem_enricher_classifier_cache_hits 67", text)
        self.assertIn("siem_enricher_classifier_cache_misses 24", text)
        self.assertIn("siem_enricher_classifier_cache_entries 24", text)

    def test_labels_and_config_changes(self) -> None:
        self.metrics.analyst_labels.inc({"label": "confirmed"})
        self.metrics.config_changes.inc({"key": "risk.high"})
        text = self.render()
        self.assertIn('siem_enricher_analyst_labels_total{label="confirmed"} 1', text)
        self.assertIn('siem_enricher_config_changes_total{key="risk.high"} 1', text)

    def test_global_registry_renders_help_lines(self) -> None:
        from siem_enricher.metrics import service_metrics
        service_metrics()
        text = render_prometheus()
        self.assertIn("# HELP", text)
        self.assertIn("siem_enricher_", text)


if __name__ == "__main__":
    unittest.main()

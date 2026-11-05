"""Конвейер обогащения события: сборка всех модулей в единый поток обработки."""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Callable, Any, Mapping, Sequence

from siem_enricher.config import AppConfig
from siem_enricher.extractor import MetadataExtractor
from siem_enricher.logging_setup import event_context, get_logger
from siem_enricher.ml import SensitivityClassifier, aggregate_level, build_classifier, load_label_weights
from siem_enricher.metrics import ServiceMetrics, service_metrics
from siem_enricher.models.enums import PolicyDecision, SensitivityLevel
from siem_enricher.models.enrichment import (
    EnrichedEvent,
    EnrichmentResult,
    PolicyOutcome,
    ProvenanceChain,
    SensitivityAssessment,
)
from siem_enricher.models.event import NormalizedEvent, utcnow
from siem_enricher.policy import PolicyEngine
from siem_enricher.provenance import ProvenanceBuilder, ProvenanceStore, build_store
from siem_enricher.enricher.risk import RiskScorer
from siem_enricher.version import ENRICHMENT_SCHEMA_VERSION, VERSION

logger = get_logger("enricher.pipeline")


class EnrichmentPipeline:
    """Основной конвейер обогащения событий."""

    def __init__(
        self,
        config: AppConfig,
        extractor: MetadataExtractor,
        classifier: SensitivityClassifier,
        builder: ProvenanceBuilder,
        scorer: RiskScorer,
        policy_engine: PolicyEngine | None = None,
        metrics: ServiceMetrics | None = None,
        store: ProvenanceStore | None = None,
    ) -> None:
        self.config = config
        self.extractor = extractor
        self.classifier = classifier
        self.builder = builder
        self.scorer = scorer
        self.policy_engine = policy_engine
        self.metrics = metrics or service_metrics()
        self.store = store or builder.store
        self.observers: list[Callable[[dict[str, Any]], None]] = []

    def add_observer(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Подписать наблюдателя на обогащённые документы (панель аналитика, отладка)."""
        self.observers.append(callback)

    def _notify_observers(self, document: dict[str, Any]) -> None:
        for callback in self.observers:
            try:
                callback(document)
            except Exception as exc:  # noqa: BLE001 - наблюдатель не должен ломать обработку
                logger.warning("Наблюдатель конвейера завершился ошибкой",
                               extra={"reason": str(exc)})

    @classmethod
    def from_config(
        cls,
        config: AppConfig,
        metrics: ServiceMetrics | None = None,
        store: ProvenanceStore | None = None,
        in_memory_store: bool = False,
        policy_engine: PolicyEngine | None = None,
    ) -> EnrichmentPipeline:
        """Собрать конвейер по конфигурации сервиса."""
        metrics = metrics or service_metrics()
        store = store or build_store(config.provenance, in_memory_for_tests=in_memory_store)
        extractor = MetadataExtractor(config.extractor)
        classifier = build_classifier(config.ml, metrics, labels_path=config.labels_path)
        label_weights = load_label_weights(config.labels_path)
        scorer = RiskScorer.from_config(config.risk, label_weights)
        builder = ProvenanceBuilder.from_config(config.provenance, store)
        engine = policy_engine or PolicyEngine.from_config(config, metrics=metrics)
        return cls(
            config=config,
            extractor=extractor,
            classifier=classifier,
            builder=builder,
            scorer=scorer,
            policy_engine=engine,
            metrics=metrics,
            store=store,
        )

    @property
    def ready(self) -> bool:
        return self.classifier is not None and self.store.ping()

    def describe(self) -> dict[str, Any]:
        return {
            "version": VERSION,
            "schema_version": ENRICHMENT_SCHEMA_VERSION,
            "classifier": self.classifier.describe(),
            "risk": self.scorer.describe(),
            "provenance": self.store.stats(),
            "policies": len(self.policy_engine.rules) if self.policy_engine else 0,
            "policy_mode": self.policy_engine.mode if self.policy_engine else None,
            "config": self.config.describe(),
        }

    def normalize(self, source: str, document: Mapping[str, Any]) -> NormalizedEvent:
        """Привести «сырое» событие SIEM к канонической модели."""
        return self.extractor.normalize(source, document)

    def enrich(self, event: NormalizedEvent, apply_policies: bool = True) -> EnrichedEvent:
        """Обогатить нормализованное событие."""
        started = time.perf_counter()
        warnings: list[str] = []

        with event_context(event.event_id):
            # 1. Классификация конфиденциальности объектов события
            per_file: list[SensitivityAssessment] = []
            if event.files:
                # объект на съёмном носителе — это место назначения копии, его имя не
                # характеризует защищаемые данные: классифицируем источник
                from siem_enricher.extractor.patterns import is_removable_path

                targets = [f.path for f in event.files if not is_removable_path(f.path)]
                try:
                    per_file = self.classifier.predict_many(targets or [f.path for f in event.files])
                except Exception as exc:  # noqa: BLE001 - сбой классификатора не должен терять событие
                    logger.error("Ошибка классификации конфиденциальности", extra={"reason": str(exc)})
                    warnings.append(f"ошибка классификации: {exc}")
                    self.metrics.ml_fallback.inc({"reason": "classification_error"})
                sensitivity = self._aggregate(per_file) if per_file else self._no_files_assessment()
            else:
                sensitivity = self._no_files_assessment()
                warnings.append("в событии не обнаружены объекты-файлы: классификация не выполнялась")

            for assessment in per_file:
                self.metrics.classified.inc({"level": assessment.level.value, "method": assessment.method})

            # 2. Цепочки происхождения
            try:
                self.builder.record(event)
                chains = self.builder.chains_for(event)
            except Exception as exc:  # noqa: BLE001
                logger.error("Ошибка построения цепочки происхождения", extra={"reason": str(exc)})
                warnings.append(f"ошибка provenance: {exc}")
                chains = []

            # 3. Оценка риска
            risk = self.scorer.score(event, sensitivity, chains, files_count=len(event.files))
            self.metrics.risk_score.observe(risk.score)
            self.metrics.risk_severity.inc({"severity": risk.severity.value})
            if chains:
                self.metrics.provenance_depth.observe(max(chain.depth for chain in chains))

            # 4. Применение политик
            result = EnrichmentResult(
                sensitivity=sensitivity,
                per_file=per_file,
                chains=chains,
                risk=risk,
                enriched_at=utcnow(),
                duration_ms=0.0,
                enricher_version=VERSION,
                schema_version=ENRICHMENT_SCHEMA_VERSION,
                warnings=list(warnings),
            )
            enriched = EnrichedEvent(event=event, enrichment=result)
            document = enriched.to_siem_document()

            if self.policy_engine is not None:
                try:
                    evaluation = self.policy_engine.evaluate(document, apply_actions=apply_policies)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Ошибка применения политик", extra={"reason": str(exc)})
                    warnings.append(f"ошибка применения политик: {exc}")
                else:
                    self._attach_policy_result(result, document, evaluation)
                    result.policy_decision = evaluation.decision

            # 5. Итоговые служебные поля
            result.duration_ms = (time.perf_counter() - started) * 1000.0
            result.warnings = warnings
            document["enrichment"]["duration_ms"] = round(result.duration_ms, 3)
            document["enrichment"]["masked_fields"] = list(result.masked_fields)
            document["enrichment"]["warnings"] = list(warnings)
            document["risk_score"] = round(risk.score, 4)
            document["risk_severity"] = risk.severity.value
            enriched.document = document

            self.metrics.enrichment_duration.observe(result.duration_ms / 1000.0)
            self.metrics.events_enriched.inc({"status": "ok"})
            logger.info(
                "Событие обогащено",
                extra={
                    "sensitivity": sensitivity.level.value,
                    "risk_score": risk.score,
                    "risk_severity": risk.severity.value,
                    "provenance_depth": result.provenance_depth,
                    "policy_decision": result.policy_decision.value,
                    "rules": [p.rule_id for p in result.policies],
                    "duration_ms": round(result.duration_ms, 3),
                },
            )
            self._notify_observers(document)
            return enriched

    def enrich_document(
        self,
        source: str,
        document: Mapping[str, Any],
        apply_policies: bool = True,
    ) -> tuple[NormalizedEvent, EnrichedEvent, dict[str, Any]]:
        """Нормализовать и обогатить «сырое» событие SIEM (основная точка входа для коннекторов)."""
        event = self.normalize(source, document)
        enriched = self.enrich(event, apply_policies=apply_policies)
        return event, enriched, enriched.siem_document()

    def classify(self, path: str) -> SensitivityAssessment:
        """Классифицировать один путь (используется API ``/v1/classify``)."""
        return self.classifier.predict(path)

    def chain(
        self,
        path: str,
        event: NormalizedEvent | None = None,
        as_of: Any | None = None,
    ) -> ProvenanceChain:
        """Получить цепочку происхождения файла."""
        return self.builder.chain_for(path, event, as_of=as_of)

    def policy_summary(self) -> list[dict[str, Any]]:
        return self.policy_engine.rules_summary() if self.policy_engine else []

    def reload_policies(self) -> int:
        if self.policy_engine is None:
            return 0
        return self.policy_engine.reload()

    def close(self) -> None:
        self.store.close()

    def _aggregate(self, assessments: Sequence[SensitivityAssessment]) -> SensitivityAssessment:
        """Свернуть оценки файлов в оценку события."""
        mode = (self.config.ml.aggregate or "max").lower()
        if not assessments:
            return self._no_files_assessment()
        if mode == "first":
            return assessments[0]
        if mode == "mean":
            best = aggregate_level(assessments)
            mean_confidence = sum(a.confidence for a in assessments) / len(assessments)
            return replace(
                best,
                confidence=round(mean_confidence, 4),
                reason=f"средняя уверенность по {len(assessments)} объектам; {best.reason}",
            )
        return aggregate_level(assessments)

    def _no_files_assessment(self) -> SensitivityAssessment:
        level = SensitivityLevel.from_value(self.config.ml.default_level, default=SensitivityLevel.INTERNAL)
        return SensitivityAssessment(
            target="",
            level=level,
            confidence=0.0,
            method="none",
            model_version=self.config.ml.model_version,
            reason="объекты классификации в событии отсутствуют",
        )

    @staticmethod
    def _attach_policy_result(
        result: EnrichmentResult,
        document: dict[str, Any],
        evaluation: Any,
    ) -> None:
        """Перенести результаты применения политик в документ и в результат обогащения."""
        outcomes: list[PolicyOutcome] = list(evaluation.outcomes)
        result.policies = outcomes
        result.policy_decision = evaluation.decision
        result.masked_fields = sorted(set(evaluation.masked_fields))

        document["policy_decision"] = evaluation.decision.value
        document["policy_actions"] = [outcome.to_dict() for outcome in outcomes]
        document["policy_rule_ids"] = [outcome.rule_id for outcome in outcomes]
        document["policy_mode"] = evaluation.mode

        tags = document.setdefault("tags", [])
        if not isinstance(tags, list):
            tags = list(tags or [])
            document["tags"] = tags
        for outcome in outcomes:
            for tag in outcome.tags:
                if tag not in tags:
                    tags.append(tag)

    def summarize(self, enriched_events: Sequence[EnrichedEvent]) -> dict[str, Any]:
        """Сводка по пакету событий — используется в CLI и отчётах ВКР."""
        levels: dict[str, int] = {}
        severities: dict[str, int] = {}
        rules: dict[str, int] = {}
        scores: list[float] = []
        durations: list[float] = []
        for enriched in enriched_events:
            level = enriched.enrichment.sensitivity.level.value
            levels[level] = levels.get(level, 0) + 1
            if enriched.enrichment.risk is not None:
                severity = enriched.enrichment.risk.severity.value
                severities[severity] = severities.get(severity, 0) + 1
                scores.append(enriched.enrichment.risk.score)
            for outcome in enriched.enrichment.policies:
                rules[outcome.rule_id] = rules.get(outcome.rule_id, 0) + 1
            durations.append(enriched.enrichment.duration_ms)
        return {
            "events": len(enriched_events),
            "sensitivity_levels": levels,
            "risk_severities": severities,
            "triggered_rules": rules,
            "mean_risk_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
            "max_risk_score": round(max(scores), 4) if scores else 0.0,
            "mean_duration_ms": round(sum(durations) / len(durations), 3) if durations else 0.0,
            "policy_decision": PolicyDecision.BLOCK.value
            if any(e.enrichment.policy_decision is PolicyDecision.BLOCK for e in enriched_events)
            else (
                PolicyDecision.ALERT.value
                if any(e.enrichment.policy_decision is PolicyDecision.ALERT for e in enriched_events)
                else PolicyDecision.ALLOW.value
            ),
        }


__all__ = ["EnrichmentPipeline"]

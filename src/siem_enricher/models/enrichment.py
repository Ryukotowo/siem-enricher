"""Результаты обогащения события и документ, возвращаемый в SIEM."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from siem_enricher.models.enums import (
    ActionStatus,
    ActionType,
    PolicyDecision,
    ProvenanceAction,
    SensitivityLevel,
    Severity,
)
from siem_enricher.models.event import NormalizedEvent, isoformat, parse_timestamp, utcnow
from siem_enricher.version import ENRICHMENT_SCHEMA_VERSION, VERSION


@dataclass(slots=True)
class SensitivityAssessment:
    """Результат классификации конфиденциальности одного объекта."""

    target: str
    level: SensitivityLevel
    confidence: float
    method: str = "heuristic"          # ml | heuristic | default | none
    model_version: str = ""
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "level": self.level.value,
            "rank": self.level.rank,
            "confidence": round(self.confidence, 4),
            "method": self.method,
            "model_version": self.model_version,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SensitivityAssessment:
        return cls(
            target=str(data.get("target", "")),
            level=SensitivityLevel.from_value(data.get("level")),
            confidence=float(data.get("confidence", 0.0)),
            method=str(data.get("method", "heuristic")),
            model_version=str(data.get("model_version", "")),
            reason=str(data.get("reason", "")),
            evidence=list(data.get("evidence") or []),
            scores={k: float(v) for k, v in (data.get("scores") or {}).items()},
        )


@dataclass(slots=True)
class ProvenanceStep:
    """Один шаг цепочки происхождения файла."""

    timestamp: datetime
    action: ProvenanceAction
    path: str
    actor_user: str | None = None
    actor_process: str | None = None
    host: str | None = None
    event_id: str | None = None
    endpoint: str | None = None
    direction: str = "self"          # self | inbound | outbound
    counterpart_path: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": isoformat(self.timestamp),
            "action": self.action.value,
            "path": self.path,
            "actor_user": self.actor_user,
            "actor_process": self.actor_process,
            "host": self.host,
            "event_id": self.event_id,
            "endpoint": self.endpoint,
            "direction": self.direction,
            "counterpart_path": self.counterpart_path,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvenanceStep:
        return cls(
            timestamp=parse_timestamp(data.get("timestamp")),
            action=ProvenanceAction.from_value(data.get("action")),
            path=str(data.get("path", "")),
            actor_user=data.get("actor_user"),
            actor_process=data.get("actor_process"),
            host=data.get("host"),
            event_id=data.get("event_id"),
            endpoint=data.get("endpoint"),
            direction=str(data.get("direction", "self")),
            counterpart_path=data.get("counterpart_path"),
            note=str(data.get("note", "")),
        )


@dataclass(slots=True)
class ProvenanceChain:
    """Цепочка происхождения конкретного файла."""

    file_path: str
    steps: list[ProvenanceStep] = field(default_factory=list)
    external_endpoints: list[str] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.steps)

    @property
    def first_seen(self) -> datetime | None:
        return min((s.timestamp for s in self.steps), default=None)

    @property
    def last_seen(self) -> datetime | None:
        return max((s.timestamp for s in self.steps), default=None)

    @property
    def actions(self) -> list[ProvenanceAction]:
        return [s.action for s in self.steps]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "depth": self.depth,
            "first_seen": isoformat(self.first_seen),
            "last_seen": isoformat(self.last_seen),
            "external_endpoints": list(self.external_endpoints),
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvenanceChain:
        return cls(
            file_path=str(data.get("file_path", "")),
            steps=[ProvenanceStep.from_dict(s) for s in data.get("steps", [])],
            external_endpoints=list(data.get("external_endpoints") or []),
        )


@dataclass(slots=True)
class RiskAssessment:
    """Оценка риска события."""

    score: float
    severity: Severity
    components: dict[str, float] = field(default_factory=dict)
    explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "severity": self.severity.value,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "explanation": list(self.explanation),
        }


@dataclass(slots=True)
class ActionOutcome:
    """Результат выполнения одного действия политики."""

    type: ActionType
    status: ActionStatus
    params: dict[str, Any] = field(default_factory=dict)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "status": self.status.value,
            "params": self.params,
            "detail": self.detail,
        }


@dataclass(slots=True)
class PolicyOutcome:
    """Результат применения одного правила политики."""

    rule_id: str
    title: str
    severity: Severity
    decision: PolicyDecision
    actions: list[ActionOutcome] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "decision": self.decision.value,
            "priority": self.priority,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "actions": [a.to_dict() for a in self.actions],
        }


@dataclass(slots=True)
class EnrichmentResult:
    """Полный результат обогащения одного события."""

    sensitivity: SensitivityAssessment
    per_file: list[SensitivityAssessment] = field(default_factory=list)
    chains: list[ProvenanceChain] = field(default_factory=list)
    risk: RiskAssessment | None = None
    policies: list[PolicyOutcome] = field(default_factory=list)
    policy_decision: PolicyDecision = PolicyDecision.ALLOW
    enriched_at: datetime = field(default_factory=utcnow)
    duration_ms: float = 0.0
    enricher_version: str = VERSION
    schema_version: str = ENRICHMENT_SCHEMA_VERSION
    warnings: list[str] = field(default_factory=list)
    masked_fields: list[str] = field(default_factory=list)

    @property
    def provenance_depth(self) -> int:
        return max((c.depth for c in self.chains), default=0)

    @property
    def external_endpoints(self) -> list[str]:
        seen: list[str] = []
        for chain in self.chains:
            for endpoint in chain.external_endpoints:
                if endpoint not in seen:
                    seen.append(endpoint)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_sensitivity": self.sensitivity.to_dict(),
            "data_sensitivity_by_file": [a.to_dict() for a in self.per_file],
            "provenance_chains": [c.to_dict() for c in self.chains],
            "risk": self.risk.to_dict() if self.risk else None,
            "policy_decision": self.policy_decision.value,
            "policy_actions": [p.to_dict() for p in self.policies],
            "enriched_at": isoformat(self.enriched_at),
            "duration_ms": round(self.duration_ms, 3),
            "enricher_version": self.enricher_version,
            "schema_version": self.schema_version,
            "warnings": list(self.warnings),
            "masked_fields": list(self.masked_fields),
        }


@dataclass(slots=True)
class EnrichedEvent:
    """Исходное событие вместе с результатом обогащения."""

    event: NormalizedEvent
    enrichment: EnrichmentResult
    #: Итоговый документ для SIEM (заполняется конвейером, включает результат применения политик)
    document: dict[str, Any] | None = None

    def siem_document(self) -> dict[str, Any]:
        """Документ для возврата в SIEM: подготовленный конвейером либо собранный «на лету»."""
        return self.document if self.document is not None else self.to_siem_document()

    def to_dict(self) -> dict[str, Any]:
        return {"event": self.event.to_dict(), "enrichment": self.enrichment.to_dict()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EnrichedEvent:
        event = NormalizedEvent.from_dict(data.get("event", {}))
        raw = data.get("enrichment", {})
        result = EnrichmentResult(
            sensitivity=SensitivityAssessment.from_dict(raw.get("data_sensitivity", {})),
            per_file=[SensitivityAssessment.from_dict(a) for a in raw.get("data_sensitivity_by_file", [])],
            chains=[ProvenanceChain.from_dict(c) for c in raw.get("provenance_chains", [])],
            risk=None,
            policies=[],
            policy_decision=PolicyDecision.from_value(raw.get("policy_decision")),
            enriched_at=parse_timestamp(raw.get("enriched_at")),
            duration_ms=float(raw.get("duration_ms", 0.0)),
            enricher_version=str(raw.get("enricher_version", VERSION)),
            schema_version=str(raw.get("schema_version", ENRICHMENT_SCHEMA_VERSION)),
            warnings=list(raw.get("warnings") or []),
            masked_fields=list(raw.get("masked_fields") or []),
        )
        return cls(event=event, enrichment=result)

    def to_siem_document(self) -> dict[str, Any]:
        """Плоское представление события с полями обогащения (совместимо с ECS-подобной схемой)."""
        event = self.event
        result = self.enrichment
        primary = event.primary_file
        risk = result.risk

        document: dict[str, Any] = {
            "@timestamp": isoformat(event.timestamp),
            "event_id": event.event_id,
            # Каноническое действие выносится на верхний уровень: по нему проверяются
            # условия правил политик и строятся корреляции в SIEM.
            "action": event.action.value,
            "event": {
                "kind": "event",
                "dataset": event.raw.get("event", {}).get("dataset") if isinstance(event.raw.get("event"), dict) else None,
                "source": event.source,
                "action": event.action.value,
                "category": _event_category(event.action),
                "original_id": event.raw.get("id") or event.raw.get("_id"),
            },
            "host": {"name": event.host} if event.host else None,
            "user": event.user.to_dict() if event.user else None,
            "process": event.process.to_dict() if event.process else None,
            "file": {
                "path": primary.path,
                "name": primary.name,
                "extension": primary.extension,
                "directory": primary.directory,
                "size": primary.size_bytes,
                "hash": {"sha256": primary.sha256} if primary.sha256 else None,
            } if primary else None,
            "files": [f.to_dict() for f in event.files],
            "remote": event.remote.to_dict() if event.remote else None,
            "rule": event.rule.to_dict() if event.rule else None,
            "tags": list(event.tags),
            "raw_event": event.raw,
        }

        from siem_enricher.extractor.patterns import is_removable_path  # локальный импорт

        document.update(
            {
                "data_sensitivity": result.sensitivity.level.value,
                "data_sensitivity_rank": result.sensitivity.level.rank,
                "data_sensitivity_ru": result.sensitivity.level.ru,
                "sensitivity_confidence": round(result.sensitivity.confidence, 4),
                "sensitivity_method": result.sensitivity.method,
                "sensitivity_model_version": result.sensitivity.model_version,
                "sensitivity_reason": result.sensitivity.reason,
                "data_sensitivity_by_file": [a.to_dict() for a in result.per_file],
                "provenance_chain": [s.to_dict() for chain in result.chains for s in chain.steps],
                "provenance_chains": [c.to_dict() for c in result.chains],
                "provenance_depth": result.provenance_depth,
                "external_destinations_count": len(result.external_endpoints),
                "external_destinations": result.external_endpoints,
                # объекты на съёмных носителях: признак подготовки выноса данных
                "removable_destinations_count": sum(
                    1 for item in event.files if is_removable_path(item.path)
                ),
                "removable_files": [item.path for item in event.files if is_removable_path(item.path)],
                "risk_score": round(risk.score, 4) if risk else 0.0,
                "risk_severity": risk.severity.value if risk else Severity.LOW.value,
                "risk_components": {k: round(v, 4) for k, v in (risk.components if risk else {}).items()},
                "risk_explanation": list(risk.explanation if risk else []),
                "policy_decision": result.policy_decision.value,
                "policy_actions": [p.to_dict() for p in result.policies],
                "policy_rule_ids": [p.rule_id for p in result.policies],
                "files_count": len(event.files),
                "enrichment": {
                    "schema_version": result.schema_version,
                    "enricher_version": result.enricher_version,
                    "enriched_at": isoformat(result.enriched_at),
                    "duration_ms": round(result.duration_ms, 3),
                    "warnings": list(result.warnings),
                    "masked_fields": list(result.masked_fields),
                },
                "siem_enricher": {
                    "version": VERSION,
                    "schema_version": result.schema_version,
                },
            }
        )

        # Теги политик дописываются в общий список тегов события
        policy_tags = [t for p in result.policies for t in p.tags]
        if policy_tags:
            tags = document.get("tags") or []
            for tag in policy_tags:
                if tag not in tags:
                    tags.append(tag)
            document["tags"] = tags

        return {k: v for k, v in document.items() if v is not None}


def _event_category(action: ProvenanceAction) -> str:
    """Категория события в терминах ECS (для корреляции в SIEM)."""
    mapping = {
        ProvenanceAction.CREATE: "file",
        ProvenanceAction.READ: "file",
        ProvenanceAction.WRITE: "file",
        ProvenanceAction.COPY: "file",
        ProvenanceAction.MOVE: "file",
        ProvenanceAction.RENAME: "file",
        ProvenanceAction.ARCHIVE: "file",
        ProvenanceAction.DELETE: "file",
        ProvenanceAction.ENCRYPT: "file",
        ProvenanceAction.DECRYPT: "file",
        ProvenanceAction.UPLOAD: "network",
        ProvenanceAction.SEND: "network",
        ProvenanceAction.EXECUTE: "process",
    }
    return mapping.get(action, "unknown")

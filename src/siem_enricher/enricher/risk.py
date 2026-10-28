"""Оценка риска события."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from siem_enricher.config import RiskConfig
from siem_enricher.models.enums import ProvenanceAction, SensitivityLevel, Severity
from siem_enricher.models.enrichment import ProvenanceChain, RiskAssessment, SensitivityAssessment
from siem_enricher.models.event import NormalizedEvent

#: Пороги по умолчанию (совпадают с config/config.example.json)
DEFAULT_THRESHOLDS: dict[str, float] = {"medium": 0.3, "high": 0.6, "critical": 0.85}


@dataclass(slots=True)
class RiskWeights:
    """Веса компонент риска (в сумме 1.0)."""

    sensitivity: float = 0.45
    confidence: float = 0.15
    action: float = 0.20
    external_destination: float = 0.10
    privileged_user: float = 0.05
    volume: float = 0.05

    def as_dict(self) -> dict[str, float]:
        return {
            "sensitivity": self.sensitivity,
            "confidence": self.confidence,
            "action": self.action,
            "external_destination": self.external_destination,
            "privileged_user": self.privileged_user,
            "volume": self.volume,
        }

    @classmethod
    def from_mapping(cls, values: Mapping[str, float] | None) -> RiskWeights:
        weights = cls()
        if not values:
            return weights
        for name in weights.as_dict():
            if name in values:
                setattr(weights, name, float(values[name]))
        return weights


@dataclass(slots=True)
class RiskScorer:
    """Вычисляет оценку риска события."""

    thresholds: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    weights: RiskWeights = field(default_factory=RiskWeights)
    action_multipliers: dict[str, float] = field(default_factory=dict)
    label_weights: dict[str, float] = field(default_factory=dict)
    volume_saturation: int = 32

    @classmethod
    def from_config(cls, config: RiskConfig, label_weights: Mapping[str, float] | None = None) -> RiskScorer:
        return cls(
            thresholds=dict(config.thresholds) or dict(DEFAULT_THRESHOLDS),
            weights=RiskWeights.from_mapping(config.weights),
            action_multipliers=dict(config.action_multipliers) or DEFAULT_ACTION_MULTIPLIERS,
            label_weights=dict(label_weights or {}),
        )

    def action_multiplier(self, action: ProvenanceAction) -> float:
        multipliers = self.action_multipliers or DEFAULT_ACTION_MULTIPLIERS
        return float(multipliers.get(action.value, multipliers.get("unknown", 0.2)))

    def severity_for(self, score: float) -> Severity:
        return Severity.from_score(score, self.thresholds)

    def score(
        self,
        event: NormalizedEvent,
        sensitivity: SensitivityAssessment,
        chains: Sequence[ProvenanceChain] = (),
        files_count: int | None = None,
    ) -> RiskAssessment:
        """Рассчитать риск события."""
        count = len(event.files) if files_count is None else files_count
        external_endpoints = self._external_endpoints(event, chains)
        is_privileged = bool(event.user and event.user.is_privileged)

        label_weight = self.label_weights.get(sensitivity.level.value, sensitivity.level.weight)
        action_multiplier = self.action_multiplier(event.action)
        volume_factor = self._volume_factor(count)

        components = {
            "sensitivity": label_weight * self.weights.sensitivity,
            "confidence": max(0.0, min(1.0, sensitivity.confidence)) * self.weights.confidence,
            "action": action_multiplier * self.weights.action,
            "external_destination": self.weights.external_destination if external_endpoints else 0.0,
            "privileged_user": self.weights.privileged_user if is_privileged else 0.0,
            "volume": self.weights.volume * volume_factor,
        }
        base = sum(components.values())
        amplifier, amplifier_notes = self._amplifier(event, sensitivity, bool(external_endpoints))

        score = max(0.0, min(1.0, base * amplifier))
        explanation = [
            f"класс {sensitivity.level.value} ({sensitivity.level.ru}), вес {label_weight:.2f}",
            f"уверенность классификации {sensitivity.confidence:.2f}",
            f"действие {event.action.value} (коэффициент {action_multiplier:.2f})",
        ]
        if external_endpoints:
            explanation.append(f"внешние адреса в событии/цепочке: {', '.join(external_endpoints[:3])}")
        if is_privileged:
            explanation.append("действие выполнено привилегированным пользователем")
        if count > 1:
            explanation.append(f"объектов в событии: {count} (насыщение объёма {volume_factor:.2f})")
        explanation.extend(amplifier_notes)

        assessment = RiskAssessment(
            score=round(score, 4),
            severity=self.severity_for(score),
            components={**components, "amplifier": amplifier},
            explanation=explanation,
        )
        return assessment

    @staticmethod
    def _external_endpoints(event: NormalizedEvent, chains: Sequence[ProvenanceChain]) -> list[str]:
        """Внешние адреса события и его цепочки происхождения."""
        endpoints: list[str] = []
        if event.remote is not None and event.remote.is_external:
            label = event.remote.url or event.remote.domain or event.remote.ip
            if label:
                endpoints.append(label)
        for chain in chains:
            for endpoint in chain.external_endpoints:
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        return endpoints

    def _volume_factor(self, files_count: int) -> float:
        if files_count <= 1:
            return 0.0
        saturation = max(2, self.volume_saturation)
        return min(1.0, math.log2(1 + files_count) / math.log2(1 + saturation))

    @staticmethod
    def _amplifier(
        event: NormalizedEvent,
        sensitivity: SensitivityAssessment,
        has_external: bool,
    ) -> tuple[float, list[str]]:
        """Усиление риска за опасные сочетания признаков."""
        amplifier = 1.0
        notes: list[str] = []
        if has_external and sensitivity.level.rank >= SensitivityLevel.CONFIDENTIAL.rank:
            amplifier *= 1.15
            notes.append("усиление ×1.15: конфиденциальные данные передаются во внешний адрес")
        if has_external and event.action in {ProvenanceAction.ARCHIVE, ProvenanceAction.ENCRYPT}:
            amplifier *= 1.10
            notes.append("усиление ×1.10: упаковка данных перед внешней передачей")
        if sensitivity.level is SensitivityLevel.SECRET and event.action.is_data_movement:
            amplifier *= 1.10
            notes.append("усиление ×1.10: перемещение объекта класса secret")
        return round(amplifier, 4), notes

    def describe(self) -> dict[str, object]:
        return {
            "thresholds": dict(self.thresholds),
            "weights": self.weights.as_dict(),
            "label_weights": dict(self.label_weights),
            "volume_saturation": self.volume_saturation,
        }


DEFAULT_ACTION_MULTIPLIERS: dict[str, float] = {
    "unknown": 0.2,
    "read": 0.25,
    "write": 0.35,
    "create": 0.30,
    "copy": 0.50,
    "move": 0.50,
    "rename": 0.40,
    "archive": 0.70,
    "encrypt": 0.85,
    "upload": 1.00,
    "send": 1.00,
    "delete": 0.60,
    "execute": 0.45,
}


def combine_scores(scores: Iterable[float], mode: str = "max") -> float:
    """Свернуть несколько оценок риска (для пакетной обработки/отчётов)."""
    values = list(scores)
    if not values:
        return 0.0
    if mode == "max":
        return max(values)
    if mode == "mean":
        return sum(values) / len(values)
    raise ValueError(f"Неизвестный режим свёртки оценок: {mode!r}")

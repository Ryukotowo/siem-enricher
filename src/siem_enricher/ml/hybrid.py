"""Гибридная классификация конфиденциальности."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from siem_enricher.logging_setup import get_logger
from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.models.enums import SensitivityLevel
from siem_enricher.models.enrichment import SensitivityAssessment

logger = get_logger("ml.hybrid")

#: Префикс ключей в ``SensitivityAssessment.scores``, помечающих признаки размещения/пометок
POLICY_SCORE_PREFIX = "policy:"


@dataclass(slots=True)
class HybridSettings:
    """Настройки объединения оценок ML-модели и правил."""

    enabled: bool = True
    #: Минимальная уверенность правил для повышения класса
    rule_min_confidence: float = 0.5
    #: Вес уверенности «победившей» оценки при объединении (0..1)
    confidence_blend: float = 0.6
    #: Разрешить правилам понижать класс модели
    allow_downgrade: bool = True
    #: Минимальная уверенность правил для понижения класса
    downgrade_min_rule_confidence: float = 0.5
    #: Понижение допускается, только если модель не уверена в своём (более высоком) классе
    downgrade_max_model_confidence: float = 0.85
    #: Приоритет признаков размещения и пометок над прогнозом модели
    policy_override: bool = True
    #: Минимальный вес признака размещения для приоритетного решения
    policy_override_min_weight: float = 0.8


def confidence_from_weight(weight: float) -> float:
    """Оценка уверенности по весу сработавших правил (та же шкала, что и в эвристиках)."""
    return min(0.95, 0.45 + 0.12 * max(0.0, weight))


class HybridSensitivityClassifier(SensitivityClassifier):
    """Объединение ML-модели (по имени) и правил (по пути, пометкам и расширению)."""

    method = "hybrid"

    def __init__(
        self,
        primary: SensitivityClassifier,
        rules: SensitivityClassifier,
        settings: HybridSettings | None = None,
        metrics: Any = None,
    ) -> None:
        self.primary = primary
        self.rules = rules
        self.settings = settings or HybridSettings()
        self.metrics = metrics
        self.model_version = f"{primary.model_version}+rules"
        self.algorithm = getattr(primary, "algorithm", primary.method)

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        path_list = [str(p) for p in paths]
        if not path_list:
            return []
        base_results = self.primary.predict_many(path_list)
        rule_results = self.rules.predict_many(path_list)
        return [
            self._combine(path, base, rule)
            for path, base, rule in zip(path_list, base_results, rule_results)
        ]

    @staticmethod
    def policy_signal(rule: SensitivityAssessment) -> tuple[SensitivityLevel, float] | None:
        """Найти наиболее сильный признак размещения/пометки в оценке правил."""
        best: tuple[SensitivityLevel, float] | None = None
        for key, value in rule.scores.items():
            if not key.startswith(POLICY_SCORE_PREFIX) or value <= 0:
                continue
            level = SensitivityLevel.from_value(key[len(POLICY_SCORE_PREFIX):], default=None)
            if level is None:
                continue
            if best is None or value > best[1]:
                best = (level, float(value))
        return best

    def _combine(
        self,
        path: str,
        base: SensitivityAssessment,
        rule: SensitivityAssessment,
    ) -> SensitivityAssessment:
        """Объединить оценки ML-модели и правил."""
        blend = max(0.0, min(1.0, self.settings.confidence_blend))
        base_rank, rule_rank = base.level.rank, rule.level.rank

        # 1. Приоритет признаков размещения и пометок (организационное решение)
        if self.settings.policy_override:
            signal = self.policy_signal(rule)
            if signal is not None and signal[1] >= self.settings.policy_override_min_weight:
                level, weight = signal
                escalates = level.rank > base_rank
                # Понижение допускается только для явного размещения в общедоступном каталоге:
                # «внутренний» каталог не делает документ безопасным, а секреты могут
                # оказаться в любом каталоге, поэтому слабые признаки вниз не применяются.
                explicit_public = level is SensitivityLevel.PUBLIC and base_rank > 0
                if level is not base.level and (escalates or explicit_public):
                    confidence = round(
                        blend * confidence_from_weight(weight) + (1.0 - blend) * base.confidence, 4
                    )
                    self._count_metric(level, "hybrid_policy_override")
                    direction = "повысил" if escalates else "понизил"
                    return self._result(
                        path, level, confidence, base, rule,
                        f"признак размещения/пометки «{level.ru}» (вес {weight:.2f}) {direction} класс "
                        f"относительно прогноза модели «{base.level.value}»",
                    )

        # 2. Повышение класса правилами содержания
        if rule_rank > base_rank and rule.confidence >= self.settings.rule_min_confidence:
            confidence = round(blend * rule.confidence + (1.0 - blend) * base.confidence, 4)
            self._count_metric(rule.level, "hybrid_escalated")
            return self._result(
                path, rule.level, confidence, base, rule,
                f"правила повысили класс с «{base.level.value}» (уверенность модели {base.confidence:.2f})",
            )

        # 3. Понижение класса: сильный признак открытости при неуверенной модели
        if (
            self.settings.allow_downgrade
            and rule_rank < base_rank
            and rule.confidence >= self.settings.downgrade_min_rule_confidence
            and base.confidence <= self.settings.downgrade_max_model_confidence
        ):
            confidence = round(blend * rule.confidence + (1.0 - blend) * base.confidence, 4)
            self._count_metric(rule.level, "hybrid_downgraded")
            return self._result(
                path, rule.level, confidence, base, rule,
                f"правила понизили класс (уверенность модели {base.confidence:.2f} "
                f"≤ {self.settings.downgrade_max_model_confidence:.2f})",
            )

        # 4. Класс модели; при совпадении классов уверенности объединяются
        confidence = (
            round(blend * base.confidence + (1.0 - blend) * rule.confidence, 4)
            if rule.level is base.level
            else base.confidence
        )
        return self._result(path, base.level, confidence, base, rule, "класс определён ML-моделью")

    def _result(
        self,
        path: str,
        level: SensitivityLevel,
        confidence: float,
        base: SensitivityAssessment,
        rule: SensitivityAssessment,
        note: str,
    ) -> SensitivityAssessment:
        """Собрать итоговую оценку с объяснением вклада обеих частей."""
        evidence = [f"ML[{name}]: {value}" for name, value in list(base.scores.items())[:3]]
        evidence.extend(f"правило: {item}" for item in rule.evidence[:4])
        return SensitivityAssessment(
            target=path,
            level=level,
            confidence=confidence,
            method=self.method,
            model_version=self.model_version,
            reason=f"{note}; ML: {base.reason}; правила: {rule.reason}",
            evidence=evidence,
            scores={f"ml:{name}": value for name, value in base.scores.items()},
        )

    def _count_metric(self, level: SensitivityLevel, method: str) -> None:
        if self.metrics is not None:
            self.metrics.classified.inc({"level": level.value, "method": method})

    def describe(self) -> dict[str, str]:
        info = super().describe()
        base = self.primary.describe()
        info.update(
            {
                "algorithm": str(base.get("algorithm", self.primary.method)),
                "artifact": str(base.get("artifact", "")),
                "device": str(base.get("device", "")),
                "categories": str(base.get("categories", "")),
                "rules": self.rules.method,
                "rule_min_confidence": str(self.settings.rule_min_confidence),
                "allow_downgrade": str(self.settings.allow_downgrade),
                "downgrade_min_rule_confidence": str(self.settings.downgrade_min_rule_confidence),
                "downgrade_max_model_confidence": str(self.settings.downgrade_max_model_confidence),
                "policy_override": str(self.settings.policy_override),
                "policy_override_min_weight": str(self.settings.policy_override_min_weight),
            }
        )
        return info

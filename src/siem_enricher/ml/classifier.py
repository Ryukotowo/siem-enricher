"""Выбор и загрузка классификатора конфиденциальности."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from siem_enricher.config import MlConfig, load_structured
from siem_enricher.logging_setup import get_logger
from siem_enricher.ml.base import SensitivityClassifier, aggregate_level
from siem_enricher.ml.fallback_rules import HeuristicSensitivityClassifier
from siem_enricher.ml.features import FEATURE_NAMES, extract_features, feature_importance_hint
from siem_enricher.ml.hybrid import HybridSettings, HybridSensitivityClassifier
from siem_enricher.ml.transformer_classifier import (
    TransformerSensitivityClassifier,
    checkpoint_info,
    is_checkpoint,
    render_text,
)
from siem_enricher.models.enums import SensitivityLevel
from siem_enricher.models.enrichment import SensitivityAssessment

logger = get_logger("ml.classifier")

HEURISTIC_VERSION = "heuristic-0.1.0"


class SklearnSensitivityClassifier(SensitivityClassifier):
    """Классификатор на основе модели scikit-learn, сохранённой через ``joblib``."""

    method = "ml-sklearn"

    def __init__(self, artifact: Mapping[str, Any], artifact_path: str | Path = "") -> None:
        self.model = artifact["model"]
        self.feature_names: tuple[str, ...] = tuple(artifact.get("feature_names") or FEATURE_NAMES)
        self.labels: tuple[str, ...] = tuple(
            artifact.get("labels") or [level.value for level in SensitivityLevel.labels()]
        )
        self.model_version = str(artifact.get("model_version", "unknown"))
        self.artifact_path = str(artifact_path)
        self.metrics: dict[str, Any] = dict(artifact.get("metrics") or {})
        self.algorithm = str(artifact.get("algorithm", type(self.model).__name__))
        self._classes = list(getattr(self.model, "classes_", self.labels))

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        path_list = list(paths)
        if not path_list:
            return []
        matrix = [
            [extract_features(path).get(name, 0.0) for name in self.feature_names]
            for path in path_list
        ]
        probabilities = self.model.predict_proba(matrix)
        results: list[SensitivityAssessment] = []
        for path, row in zip(path_list, probabilities):
            pairs = sorted(zip(self._classes, row), key=lambda item: float(item[1]), reverse=True)
            best_label, best_probability = pairs[0]
            level = SensitivityLevel.from_value(best_label, default=SensitivityLevel.INTERNAL)
            results.append(
                SensitivityAssessment(
                    target=path,
                    level=level,
                    confidence=round(float(best_probability), 4),
                    method=self.method,
                    model_version=self.model_version,
                    reason=f"модель {self.algorithm} ({self.model_version})",
                    evidence=feature_importance_hint(extract_features(path)),
                    scores={str(label): round(float(prob), 4) for label, prob in pairs},
                )
            )
        return results

    def describe(self) -> dict[str, str]:
        info = super().describe()
        info.update({"algorithm": self.algorithm, "artifact": self.artifact_path})
        return info


def load_artifact(path: str | Path) -> dict[str, Any] | None:
    """Загрузить joblib-артефакт модели, если он существует."""
    artifact_path = Path(path)
    if not artifact_path.exists() or artifact_path.is_dir():
        return None
    try:
        import joblib
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise RuntimeError(
            "Для загрузки ML-модели требуется joblib: pip install 'siem-enricher[ml]'"
        ) from exc
    artifact = joblib.load(artifact_path)
    if not isinstance(artifact, Mapping) or "model" not in artifact:
        raise ValueError(f"Некорректный формат артефакта модели: {artifact_path}")
    return dict(artifact)


def resolve_labels_path(config: MlConfig, labels_path: str | Path | None = None) -> Path:
    """Определить путь к реестру классов конфиденциальности."""
    if labels_path is not None:
        return Path(labels_path)
    candidate = Path(config.labels_file)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    for parent in (Path.cwd(), *Path.cwd().parents):
        probe = parent / candidate
        if probe.exists():
            return probe
    return candidate


def load_category_map(path: str | Path) -> dict[str, str]:
    """Прочитать соответствие «категория модели -> класс конфиденциальности»."""
    try:
        data = load_structured(path)
    except Exception as exc:  # noqa: BLE001 - отсутствие карты не критично
        logger.warning("Не удалось прочитать карту категорий модели",
                       extra={"path": str(path), "reason": str(exc)})
        return {}
    categories = data.get("model_categories") or {}
    result: dict[str, str] = {}
    if isinstance(categories, Mapping):
        for name, value in categories.items():
            if isinstance(value, Mapping):
                result[str(name)] = str(value.get("sensitivity", "internal"))
            else:
                result[str(name)] = str(value)
    return result


def load_label_weights(path: str | Path) -> dict[str, float]:
    """Прочитать веса классов конфиденциальности для риск-скоринга."""
    try:
        data = load_structured(path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Не удалось прочитать реестр классов, используются веса по умолчанию",
                       extra={"path": str(path), "reason": str(exc)})
        return {}
    weights: dict[str, float] = {}
    for item in data.get("labels", []):
        if isinstance(item, Mapping) and "id" in item and "weight" in item:
            weights[str(item["id"])] = float(item["weight"])
    unknown = data.get("unknown_label")
    if isinstance(unknown, Mapping) and "weight" in unknown:
        weights["unknown"] = float(unknown["weight"])
    return weights


def labels_catalog(path: str | Path) -> list[dict[str, Any]]:
    """Каталог классов конфиденциальности для API и отчётов."""
    try:
        data = load_structured(path)
    except Exception:  # noqa: BLE001
        return []
    catalog = [dict(item) for item in data.get("labels", []) if isinstance(item, Mapping)]
    unknown = data.get("unknown_label")
    if isinstance(unknown, Mapping):
        catalog.append(dict(unknown))
    return catalog


def model_categories_catalog(path: str | Path) -> list[dict[str, Any]]:
    """Каталог категорий ML-модели и их отображения на классы конфиденциальности."""
    try:
        data = load_structured(path)
    except Exception:  # noqa: BLE001
        return []
    categories = data.get("model_categories") or {}
    if not isinstance(categories, Mapping):
        return []
    result: list[dict[str, Any]] = []
    for name, value in categories.items():
        if isinstance(value, Mapping):
            item = dict(value)
            item.setdefault("category", str(name))
            result.append(item)
    return result


def describe_ml_stack(config: MlConfig, labels_path: str | Path | None = None) -> dict[str, Any]:
    """Сведения об ML-контуре: что настроено и что фактически доступно на диске."""
    artifact = Path(config.artifact_path)
    return {
        "type": config.type,
        "artifact_path": str(artifact),
        "artifact_exists": artifact.exists(),
        "checkpoint": is_checkpoint(artifact),
        "checkpoint_info": checkpoint_info(artifact) if artifact.is_dir() else {},
        "labels_file": str(resolve_labels_path(config, labels_path)),
        "categories": load_category_map(resolve_labels_path(config, labels_path)),
        "hybrid_enabled": config.hybrid_enabled,
        "device": config.device,
        "max_length": config.max_length,
        "text_template": config.text_template,
        "resolved_text_example": render_text(config.text_template, path=r"C:\HR\Ведомость_2025.xlsx"),
    }


def build_classifier(
    config: MlConfig,
    metrics: Any = None,
    labels_path: str | Path | None = None,
) -> SensitivityClassifier:
    """Создать классификатор согласно конфигурации."""
    mode = (config.type or "auto").lower()
    explicit_version = "" if (config.model_version or "auto").lower() in {"auto", ""} else config.model_version

    rules = HeuristicSensitivityClassifier(
        default_level=SensitivityLevel.from_value(config.default_level, default=SensitivityLevel.INTERNAL),
        model_version=explicit_version or HEURISTIC_VERSION,
        confidence_floor=config.confidence_floor,
    )
    if mode == "heuristic":
        return rules

    hybrid_settings = HybridSettings(
        enabled=config.hybrid_enabled,
        rule_min_confidence=config.hybrid_rule_min_confidence,
        confidence_blend=config.hybrid_confidence_blend,
        allow_downgrade=config.hybrid_allow_downgrade,
        downgrade_min_rule_confidence=config.hybrid_downgrade_min_rule_confidence,
        downgrade_max_model_confidence=config.hybrid_downgrade_max_model_confidence,
        policy_override=config.hybrid_policy_override,
        policy_override_min_weight=config.hybrid_policy_override_min_weight,
    )
    artifact = Path(config.artifact_path)
    category_map = load_category_map(resolve_labels_path(config, labels_path))

    # 1. Трансформер (HF-чекпоинт)
    if mode in {"auto", "transformer", "hybrid"}:
        if is_checkpoint(artifact):
            try:
                classifier: SensitivityClassifier = _build_transformer(
                    config, category_map, explicit_version, metrics
                )
            except Exception as exc:  # noqa: BLE001 - в режиме auto деградируем к правилам
                if mode in {"transformer", "hybrid"}:
                    raise
                logger.warning(
                    "Не удалось загрузить трансформер, используются правила",
                    extra={"artifact": str(artifact), "reason": str(exc)},
                )
                if metrics is not None:
                    metrics.ml_fallback.inc({"reason": type(exc).__name__})
            else:
                # Гибрид включается только для режимов auto/hybrid: режим transformer
                # означает «использовать/оценивать чистую модель».
                if config.hybrid_enabled and mode in {"auto", "hybrid"}:
                    logger.info(
                        "Используется гибридная схема: ML по имени файла + правила по каталогу и расширению"
                    )
                    return HybridSensitivityClassifier(classifier, rules, hybrid_settings, metrics=metrics)
                return classifier
        elif mode in {"transformer", "hybrid"}:
            raise FileNotFoundError(
                f"ml.type={mode}, но HF-чекпоинт не найден в {artifact}. "
                "Скопируйте каталог модели в ml/artifacts/ или укажите ml.artifact_path"
            )
        else:
            if metrics is not None:
                metrics.ml_fallback.inc({"reason": "checkpoint_missing"})
            logger.info("HF-чекпоинт не найден, проверяю альтернативные артефакты",
                        extra={"artifact": str(artifact)})

    # 2. Альтернатива: sklearn-модель в joblib
    if mode in {"auto", "sklearn"}:
        if artifact.exists() and artifact.is_file():
            try:
                data = load_artifact(artifact)
            except Exception as exc:  # noqa: BLE001
                if mode == "sklearn":
                    raise
                logger.warning("Не удалось загрузить joblib-модель, используются правила",
                               extra={"artifact": str(artifact), "reason": str(exc)})
                if metrics is not None:
                    metrics.ml_fallback.inc({"reason": type(exc).__name__})
            else:
                if data is not None:
                    sklearn_model = SklearnSensitivityClassifier(data, artifact)
                    logger.info("Загружена sklearn-модель классификации",
                                extra={"model_version": sklearn_model.model_version})
                    if config.hybrid_enabled:
                        return HybridSensitivityClassifier(
                            sklearn_model, rules, hybrid_settings, metrics=metrics
                        )
                    return sklearn_model
        elif mode == "sklearn":
            raise FileNotFoundError(
                f"ml.type=sklearn, но артефакт модели не найден: {artifact}. "
                "Обучите модель: python ml/training/train_sklearn.py"
            )

    # 3. Запасной вариант — детерминированные правила
    if metrics is not None:
        metrics.ml_fallback.inc({"reason": "artifact_missing"})
    logger.warning(
        "ML-модель не найдена: используется эвристический классификатор. "
        "Функциональность сохраняется, но точность ниже",
        extra={"artifact": str(artifact), "type": config.type},
    )
    return rules


def _build_transformer(
    config: MlConfig,
    category_map: Mapping[str, str],
    explicit_version: str,
    metrics: Any,
) -> TransformerSensitivityClassifier:
    """Загрузить трансформер-классификатор из чекпоинта."""
    return TransformerSensitivityClassifier(
        model_path=config.artifact_path,
        category_map=category_map,
        label_encoder_file=config.label_encoder_file,
        max_length=config.max_length,
        batch_size=config.batch_size,
        device=config.device,
        text_template=config.text_template,
        model_version=explicit_version,
        unknown_category_level=SensitivityLevel.from_value(
            config.default_level, default=SensitivityLevel.INTERNAL
        ),
        metrics=metrics,
    )


__all__ = [
    "HEURISTIC_VERSION",
    "SklearnSensitivityClassifier",
    "aggregate_level",
    "build_classifier",
    "describe_ml_stack",
    "labels_catalog",
    "load_artifact",
    "load_category_map",
    "load_label_weights",
    "model_categories_catalog",
    "resolve_labels_path",
]

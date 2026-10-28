"""Классификатор конфиденциальности на основе дообученного трансформера (HuggingFace)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from siem_enricher.logging_setup import get_logger
from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.models.enums import SensitivityLevel
from siem_enricher.models.enrichment import SensitivityAssessment
from siem_enricher.models.event import split_path

logger = get_logger("ml.transformer")

INSTALL_HINT = (
    "Для трансформер-классификатора требуются torch и transformers: "
    "pip install 'siem-enricher[transformer]'"
)

#: Файлы, наличие которых говорит о том, что перед нами HF-чекпоинт
REQUIRED_CHECKPOINT_FILES = ("config.json",)
WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")


def is_checkpoint(path: str | Path) -> bool:
    """Похож ли путь на каталог HF-чекпоинта."""
    directory = Path(path)
    if not directory.is_dir():
        return False
    if not (directory / "config.json").exists():
        return False
    if not any((directory / name).exists() for name in WEIGHT_FILES):
        return False
    return any(
        (directory / name).exists()
        for name in ("tokenizer.json", "tokenizer_config.json", "vocab.txt", "spiece.model")
    )


def checkpoint_info(path: str | Path) -> dict[str, Any]:
    """Прочитать основные сведения о чекпоинте (для CLI и логов)."""
    config_path = Path(path) / "config.json"
    if not config_path.exists():
        return {}
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        "architectures": config.get("architectures"),
        "model_type": config.get("model_type"),
        "num_labels": len(config.get("id2label") or {}),
        "id2label": config.get("id2label"),
        "max_position_embeddings": config.get("max_position_embeddings"),
        "transformers_version": config.get("transformers_version"),
    }


def resolve_device(spec: str = "auto") -> str:
    """Определить устройство вычислений: ``auto`` -> CUDA при наличии, иначе CPU."""
    value = (spec or "auto").strip().lower()
    if value in {"auto", ""}:
        try:
            import torch

            return "cuda" if torch.cuda.is_available() else "cpu"
        except ImportError:  # pragma: no cover - проверка выполняется при загрузке модели
            return "cpu"
    return value


def render_text(
    template: str,
    *,
    path: str,
    action: str = "",
) -> str:
    """Сформировать текст для модели по шаблону."""
    directory, name, extension = split_path(path or "")
    stem = name[: -len(extension)] if extension else name
    values = {
        "name": name,
        "stem": stem,
        "extension": extension,
        "directory": directory,
        "path": path or "",
        "action": action,
    }
    try:
        return str(template or "{name}").format(**values).strip()
    except KeyError as exc:  # неизвестная подстановка в шаблоне
        logger.warning("Неизвестная подстановка в ml.text_template", extra={"placeholder": str(exc)})
        return name


class TransformerSensitivityClassifier(SensitivityClassifier):
    """Классификация конфиденциальности дообученной моделью (mBERT/ruBERT и аналоги)."""

    method = "transformer"

    def __init__(
        self,
        model_path: str | Path,
        category_map: Mapping[str, str] | None = None,
        label_encoder_file: str = "label_encoder.pkl",
        max_length: int = 64,
        batch_size: int = 16,
        device: str = "auto",
        text_template: str = "{name}",
        model_version: str = "",
        unknown_category_level: SensitivityLevel = SensitivityLevel.INTERNAL,
        metrics: Any = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.category_map = {str(k): str(v) for k, v in (category_map or {}).items()}
        self.label_encoder_file = label_encoder_file
        self.max_length = int(max_length)
        self.batch_size = max(1, int(batch_size))
        self.device_spec = device
        self.text_template = text_template
        self.unknown_category_level = unknown_category_level
        self.metrics = metrics
        self.model_version = model_version or self._derive_version()

        self._model: Any = None
        self._tokenizer: Any = None
        self._torch: Any = None
        self.device = resolve_device(device)
        self.categories: list[str] = []
        self.algorithm = ""
        self._load()

    def _derive_version(self) -> str:
        info = checkpoint_info(self.model_path)
        model_type = info.get("model_type") or "transformer"
        return f"{model_type}-{self.model_path.name}"

    def _load(self) -> None:
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Каталог модели не найден: {self.model_path}. "
                "Скопируйте чекпоинт в ml/artifacts/ или укажите ml.artifact_path"
            )
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - зависит от окружения
            raise RuntimeError(INSTALL_HINT) from exc

        self._torch = torch
        logger.info("Загрузка трансформер-классификатора",
                    extra={"path": str(self.model_path), "device": self.device})
        self._tokenizer = AutoTokenizer.from_pretrained(str(self.model_path), local_files_only=True)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            str(self.model_path), local_files_only=True
        )
        self._model.to(self.device)
        self._model.eval()
        self.algorithm = type(self._model).__name__
        self.categories = self._load_categories()
        if not self.categories:
            raise RuntimeError(
                f"Не удалось определить категории модели в {self.model_path}: "
                f"нет файла {self.label_encoder_file} и осмысленных id2label"
            )
        unknown = [c for c in self.categories if c not in self.category_map]
        if unknown:
            logger.warning(
                "Категории модели отсутствуют в карте соответствия — будет использован класс по умолчанию",
                extra={"categories": unknown, "default": self.unknown_category_level.value},
            )
        logger.info(
            "Трансформер-классификатор готов",
            extra={"categories": self.categories, "max_length": self.max_length,
                   "device": self.device, "algorithm": self.algorithm},
        )

    def _load_categories(self) -> list[str]:
        """Определить имена категорий: сначала label_encoder, затем id2label."""
        encoder_path = self.model_path / self.label_encoder_file
        if encoder_path.exists():
            try:
                import joblib

                encoder = joblib.load(encoder_path)
                classes = list(getattr(encoder, "classes_", []))
                if classes:
                    return [str(item) for item in classes]
            except Exception as exc:  # noqa: BLE001 - деградируем к id2label
                logger.warning("Не удалось прочитать label_encoder, использую id2label из config.json",
                               extra={"path": str(encoder_path), "reason": str(exc)})
        id2label = dict(getattr(self._model.config, "id2label", {}) or {})
        labels = [str(id2label.get(index, "")) for index in range(len(id2label))]
        if all(label.startswith("LABEL_") for label in labels if label):
            return []
        return [label for label in labels if label]

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        path_list = [str(p) for p in paths]
        if not path_list:
            return []
        texts = [render_text(self.text_template, path=path) for path in path_list]
        results: list[SensitivityAssessment] = []
        for start in range(0, len(texts), self.batch_size):
            chunk_texts = texts[start : start + self.batch_size]
            chunk_paths = path_list[start : start + self.batch_size]
            probabilities = self._infer(chunk_texts)
            for path, row in zip(chunk_paths, probabilities):
                results.append(self._build_assessment(path, row))
        return results

    def _infer(self, texts: Sequence[str]) -> list[list[float]]:
        torch = self._torch
        encoded = self._tokenizer(
            list(texts),
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            padding=True,
        )
        encoded = {key: value.to(self.device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = self._model(**encoded).logits
            probabilities = torch.softmax(logits, dim=-1).cpu().tolist()
        return probabilities

    def _build_assessment(self, path: str, row: Sequence[float]) -> SensitivityAssessment:
        pairs = sorted(zip(self.categories, row), key=lambda item: float(item[1]), reverse=True)
        if not pairs:
            return SensitivityAssessment(
                target=path,
                level=self.unknown_category_level,
                confidence=0.0,
                method=self.method,
                model_version=self.model_version,
                reason="модель не вернула вероятностей",
            )
        category, probability = str(pairs[0][0]), float(pairs[0][1])
        mapped = self.category_map.get(category)
        if mapped is None:
            level = self.unknown_category_level
            reason = f"категория модели «{category}» не сопоставлена классу конфиденциальности"
            if self.metrics is not None:
                self.metrics.ml_fallback.inc({"reason": "unknown_category"})
        else:
            level = SensitivityLevel.from_value(mapped, default=self.unknown_category_level)
            reason = f"модель {self.algorithm}: категория «{category}» → класс «{level.value}»"

        evidence = [f"{name}: {value:.3f}" for name, value in pairs[:3]]
        return SensitivityAssessment(
            target=path,
            level=level,
            confidence=round(probability, 4),
            method=self.method,
            model_version=self.model_version,
            reason=reason,
            evidence=evidence,
            scores={str(name): round(float(value), 4) for name, value in pairs},
        )

    def describe(self) -> dict[str, str]:
        info = super().describe()
        info.update(
            {
                "algorithm": self.algorithm,
                "artifact": str(self.model_path),
                "device": self.device,
                "max_length": str(self.max_length),
                "categories": ", ".join(self.categories),
            }
        )
        return info

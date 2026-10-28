"""Конфигурация сервиса: загрузка, подстановка переменных окружения, валидация."""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULTS: dict[str, Any] = {
    "service": {
        "name": "siem-enricher",
        "instance_id": "local-1",
        "environment": "dev",
        "log_level": "INFO",
        "log_format": "json",
    },
    "source": {"type": "file_replay", "options": {}},
    "sink": {"type": "file_jsonl", "options": {"path": "var/enriched_events.jsonl"}},
    "extractor": {
        "max_files_per_event": 32,
        "max_users_per_event": 8,
        "drop_system_paths": True,
        "system_path_prefixes": [
            "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
            "/proc/", "/sys/", "/dev/", "/usr/lib/", "/usr/share/",
        ],
        "aliases": {},
        "scan_embedded_paths": True,
        "max_embedded_paths": 8,
    },
    "ml": {
        "type": "auto",
        "artifact_path": "ml/artifacts/sensitivity_transformer",
        "label_encoder_file": "label_encoder.pkl",
        "labels_file": "config/sensitivity_labels.json",
        "model_version": "auto",
        "default_level": "internal",
        "confidence_floor": 0.35,
        "aggregate": "max",
        "max_length": 64,
        "batch_size": 16,
        "device": "auto",
        "text_template": "{name}",
        "hybrid_enabled": True,
        "hybrid_rule_min_confidence": 0.5,
        "hybrid_confidence_blend": 0.6,
        "hybrid_allow_downgrade": True,
        "hybrid_downgrade_min_rule_confidence": 0.5,
        "hybrid_downgrade_max_model_confidence": 0.85,
        "hybrid_policy_override": True,
        "hybrid_policy_override_min_weight": 0.8,
    },
    "provenance": {
        "backend": "sqlite",
        "sqlite_path": "var/state/provenance.db",
        "redis_url": "",
        "ttl_seconds": 604800,
        "max_chain_depth": 16,
        "external_actions": ["upload", "send", "post", "webhook"],
    },
    "risk": {
        "thresholds": {"medium": 0.3, "high": 0.6, "critical": 0.85},
        "weights": {
            "sensitivity": 0.45,
            "confidence": 0.15,
            "action": 0.20,
            "external_destination": 0.10,
            "privileged_user": 0.05,
            "volume": 0.05,
        },
        "action_multipliers": {
            "unknown": 0.2, "read": 0.25, "write": 0.35, "create": 0.3, "copy": 0.5,
            "move": 0.5, "rename": 0.4, "archive": 0.7, "encrypt": 0.85,
            "upload": 1.0, "send": 1.0, "delete": 0.6, "execute": 0.45,
        },
    },
    "policy": {
        "file": "config/policies.json",
        "mode": "dry_run",
        "audit_log": "var/logs/policy_audit.jsonl",
        "stop_on_block": True,
        "webhook_url": "",
    },
    "http": {"host": "0.0.0.0", "port": 8080, "metrics_port": 9101},
    "runtime": {
        "workers": 1,
        "queue_max_size": 10000,
        "shutdown_grace_seconds": 15,
        "checkpoint_path": "var/state/checkpoint.json",
    },
}


class ConfigError(ValueError):
    """Ошибка конфигурации с понятным человеку сообщением."""


def expand_env(value: Any, environ: Mapping[str, str] | None = None) -> Any:
    """Рекурсивно подставить ``${VAR}`` и ``${VAR:-default}`` в строки конфигурации."""
    env = os.environ if environ is None else environ
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in env and env[name] != "":
                return env[name]
            if default is not None:
                return default
            raise ConfigError(f"Не задана переменная окружения {name!r}, требуемая конфигурацией")
        return ENV_PATTERN.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v, env) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, env) for k, v in value.items()}
    return value


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Рекурсивно объединить словари: значения ``override`` приоритетнее."""
    result = copy.deepcopy(dict(base))
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, Mapping):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_structured(path: str | Path, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Прочитать JSON или YAML (если установлен PyYAML) с подстановкой переменных окружения."""
    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"Файл не найден: {file_path}")
    text = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - зависит от окружения
            raise ConfigError(
                f"Для чтения {file_path.name} нужен PyYAML: pip install 'siem-enricher[config]'"
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    if not isinstance(data, dict):
        raise ConfigError(f"Ожидался объект верхнего уровня в {file_path}")
    expanded = expand_env(data, environ)
    if not isinstance(expanded, dict):  # pragma: no cover - защита от некорректного типа
        raise ConfigError(f"Некорректная структура {file_path}")
    return expanded


@dataclass(slots=True)
class ServiceConfig:
    name: str = "siem-enricher"
    instance_id: str = "local-1"
    environment: str = "dev"
    log_level: str = "INFO"
    log_format: str = "json"


@dataclass(slots=True)
class ConnectorConfig:
    type: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExtractorConfig:
    max_files_per_event: int = 32
    max_users_per_event: int = 8
    drop_system_paths: bool = True
    system_path_prefixes: list[str] = field(default_factory=list)
    aliases: dict[str, list[str]] = field(default_factory=dict)
    scan_embedded_paths: bool = True
    max_embedded_paths: int = 8


@dataclass(slots=True)
class MlConfig:
    """Настройки классификатора конфиденциальности."""

    type: str = "auto"
    artifact_path: str = "ml/artifacts/sensitivity_transformer"
    label_encoder_file: str = "label_encoder.pkl"
    labels_file: str = "config/sensitivity_labels.json"
    model_version: str = "auto"
    default_level: str = "internal"
    confidence_floor: float = 0.35
    aggregate: str = "max"
    max_length: int = 64
    batch_size: int = 16
    device: str = "auto"
    text_template: str = "{name}"
    hybrid_enabled: bool = True
    hybrid_rule_min_confidence: float = 0.5
    hybrid_confidence_blend: float = 0.6
    hybrid_allow_downgrade: bool = True
    hybrid_downgrade_min_rule_confidence: float = 0.5
    hybrid_downgrade_max_model_confidence: float = 0.85
    hybrid_policy_override: bool = True
    hybrid_policy_override_min_weight: float = 0.8


@dataclass(slots=True)
class ProvenanceConfig:
    backend: str = "sqlite"
    sqlite_path: str = "var/state/provenance.db"
    redis_url: str = ""
    ttl_seconds: int = 604800
    max_chain_depth: int = 16
    external_actions: list[str] = field(default_factory=lambda: ["upload", "send"])


@dataclass(slots=True)
class RiskConfig:
    thresholds: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)
    action_multipliers: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class PolicyConfig:
    file: str = "config/policies.json"
    mode: str = "dry_run"
    audit_log: str = "var/logs/policy_audit.jsonl"
    stop_on_block: bool = True
    webhook_url: str = ""


@dataclass(slots=True)
class HttpConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    metrics_port: int = 9101


@dataclass(slots=True)
class RuntimeConfig:
    workers: int = 1
    queue_max_size: int = 10000
    shutdown_grace_seconds: int = 15
    checkpoint_path: str = "var/state/checkpoint.json"


@dataclass(slots=True)
class AppConfig:
    """Полная конфигурация сервиса."""

    service: ServiceConfig
    source: ConnectorConfig
    sink: ConnectorConfig
    extractor: ExtractorConfig
    ml: MlConfig
    provenance: ProvenanceConfig
    risk: RiskConfig
    policy: PolicyConfig
    http: HttpConfig
    runtime: RuntimeConfig
    base_dir: Path = field(default_factory=Path.cwd)
    path: Path | None = None

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        base_dir: str | Path | None = None,
        path: str | Path | None = None,
    ) -> AppConfig:
        merged = deep_merge(DEFAULTS, data)
        cfg_path = Path(path) if path else None
        if base_dir is None:
            base_dir = _guess_base_dir(cfg_path)
        return cls(
            service=ServiceConfig(**merged["service"]),
            source=ConnectorConfig(**merged["source"]),
            sink=ConnectorConfig(**merged["sink"]),
            extractor=ExtractorConfig(**merged["extractor"]),
            ml=MlConfig(**merged["ml"]),
            provenance=ProvenanceConfig(**merged["provenance"]),
            risk=RiskConfig(**merged["risk"]),
            policy=PolicyConfig(**merged["policy"]),
            http=HttpConfig(**merged["http"]),
            runtime=RuntimeConfig(**merged["runtime"]),
            base_dir=Path(base_dir),
            path=cfg_path,
        )

    def resolve(self, value: str | Path) -> Path:
        """Разрешить путь относительно корня проекта."""
        p = Path(value)
        return p if p.is_absolute() else (self.base_dir / p)

    @property
    def policy_path(self) -> Path:
        return self.resolve(self.policy.file)

    @property
    def labels_path(self) -> Path:
        return self.resolve(self.ml.labels_file)

    @property
    def artifact_path(self) -> Path:
        return self.resolve(self.ml.artifact_path)

    @property
    def audit_log_path(self) -> Path:
        return self.resolve(self.policy.audit_log)

    @property
    def checkpoint_path(self) -> Path:
        return self.resolve(self.runtime.checkpoint_path)

    @property
    def sqlite_path(self) -> Path:
        return self.resolve(self.provenance.sqlite_path)

    def validate(self) -> list[str]:
        """Проверить конфигурацию. Возвращает список найденных проблем."""
        errors: list[str] = []
        if not self.source.type:
            errors.append("source.type не задан")
        if not self.sink.type:
            errors.append("sink.type не задан")
        if self.ml.type not in {"auto", "hybrid", "transformer", "sklearn", "heuristic"}:
            errors.append(
                f"ml.type={self.ml.type!r}: допустимо auto|hybrid|transformer|sklearn|heuristic"
            )
        if self.ml.max_length <= 0:
            errors.append("ml.max_length должен быть > 0")
        if self.ml.batch_size <= 0:
            errors.append("ml.batch_size должен быть > 0")
        device = (self.ml.device or "auto").lower()
        if device not in {"auto", "cpu", "mps"} and not device.startswith("cuda"):
            errors.append(f"ml.device={self.ml.device!r}: допустимо auto|cpu|cuda|cuda:N")
        if not 0.0 <= self.ml.hybrid_rule_min_confidence <= 1.0:
            errors.append("ml.hybrid_rule_min_confidence должен быть в диапазоне 0..1")
        if not 0.0 <= self.ml.hybrid_confidence_blend <= 1.0:
            errors.append("ml.hybrid_confidence_blend должен быть в диапазоне 0..1")
        if not 0.0 <= self.ml.hybrid_downgrade_min_rule_confidence <= 1.0:
            errors.append("ml.hybrid_downgrade_min_rule_confidence должен быть в диапазоне 0..1")
        if not 0.0 <= self.ml.hybrid_downgrade_max_model_confidence <= 1.0:
            errors.append("ml.hybrid_downgrade_max_model_confidence должен быть в диапазоне 0..1")
        if self.ml.hybrid_policy_override_min_weight < 0:
            errors.append("ml.hybrid_policy_override_min_weight не может быть отрицательным")
        if self.ml.aggregate not in {"max", "mean", "first"}:
            errors.append(f"ml.aggregate={self.ml.aggregate!r}: допустимо max|mean|first")
        if self.provenance.backend not in {"memory", "sqlite", "redis"}:
            errors.append(
                f"provenance.backend={self.provenance.backend!r}: допустимо memory|sqlite|redis"
            )
        if self.policy.mode not in {"dry_run", "live"}:
            errors.append(f"policy.mode={self.policy.mode!r}: допустимо dry_run|live")
        if self.policy.mode == "live" and self.service.environment == "dev":
            errors.append(
                "policy.mode=live в окружении dev: включение реальных блокировок требует "
                "явного environment != dev"
            )

        th = self.risk.thresholds
        medium, high, critical = th.get("medium"), th.get("high"), th.get("critical")
        if None in (medium, high, critical):
            errors.append("risk.thresholds должны содержать medium, high, critical")
        elif not (0 <= medium < high < critical <= 1):
            errors.append("risk.thresholds должны удовлетворять 0 <= medium < high < critical <= 1")

        for name, weight in self.risk.weights.items():
            if weight < 0:
                errors.append(f"risk.weights.{name} < 0")
        if not self.risk.action_multipliers:
            errors.append("risk.action_multipliers пуст")
        for name, mult in self.risk.action_multipliers.items():
            if not 0 <= mult <= 1:
                errors.append(f"risk.action_multipliers.{name}={mult}: ожидается диапазон 0..1")

        if self.extractor.max_files_per_event <= 0:
            errors.append("extractor.max_files_per_event должен быть > 0")
        if self.provenance.max_chain_depth <= 0:
            errors.append("provenance.max_chain_depth должен быть > 0")
        return errors

    def describe(self) -> dict[str, Any]:
        """Краткое описание конфигурации для логов и ответа ``/v1/version``."""
        return {
            "instance_id": self.service.instance_id,
            "environment": self.service.environment,
            "source": self.source.type,
            "sink": self.sink.type,
            "ml": self.ml.type,
            "provenance": self.provenance.backend,
            "policy_mode": self.policy.mode,
            "base_dir": str(self.base_dir),
        }


def _guess_base_dir(cfg_path: Path | None) -> Path:
    """Определить корень проекта по расположению конфигурации."""
    if cfg_path is None:
        return Path.cwd()
    resolved = cfg_path.resolve()
    parent = resolved.parent
    if parent.name in {"config", "conf", "etc"}:
        return parent.parent
    return parent


def load_config(
    path: str | Path = "config/config.example.json",
    environ: Mapping[str, str] | None = None,
    validate: bool = True,
) -> AppConfig:
    """Загрузить конфигурацию из файла и при необходимости проверить её."""
    data = load_structured(path, environ)
    cfg = AppConfig.from_dict(data, path=path)
    if validate:
        errors = cfg.validate()
        if errors:
            raise ConfigError("Некорректная конфигурация:\n  - " + "\n  - ".join(errors))
    return cfg

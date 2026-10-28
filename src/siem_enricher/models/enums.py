"""Перечисления предметной области: классы конфиденциальности, действия, сущности, решения."""

from __future__ import annotations

from enum import Enum
from typing import Any


class SensitivityLevel(str, Enum):
    """Класс конфиденциальности объекта (файла, каталога, документа)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Числовой ранг для сравнений в правилах политик."""
        return _SENSITIVITY_RANK[self.value]

    @property
    def ru(self) -> str:
        return _SENSITIVITY_RU[self.value]

    @property
    def weight(self) -> float:
        """Вклад класса в оценку риска (0..1)."""
        return _SENSITIVITY_WEIGHT[self.value]

    def at_least(self, other: SensitivityLevel) -> bool:
        return self.rank >= other.rank

    @classmethod
    def from_value(cls, value: Any, default: SensitivityLevel | None = None) -> SensitivityLevel:
        """Привести произвольное значение (в т.ч. русское название) к классу."""
        if isinstance(value, cls):
            return value
        if value is None:
            return default or cls.UNKNOWN
        text = str(value).strip().lower()
        if not text:
            return default or cls.UNKNOWN
        if text in _SENSITIVITY_ALIASES:
            return cls(_SENSITIVITY_ALIASES[text])
        for level in cls:
            if level.value == text or level.ru.lower() == text:
                return level
        for alias, target in _SENSITIVITY_ALIASES.items():
            if alias in text:
                return cls(target)
        return default or cls.UNKNOWN

    @classmethod
    def labels(cls) -> list[SensitivityLevel]:
        """Классы в порядке возрастания ранга (без ``unknown``)."""
        return [cls.PUBLIC, cls.INTERNAL, cls.CONFIDENTIAL, cls.SECRET]


_SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "secret": 3, "unknown": 1}
_SENSITIVITY_WEIGHT = {"public": 0.05, "internal": 0.35, "confidential": 0.7, "secret": 1.0, "unknown": 0.4}
_SENSITIVITY_RU = {
    "public": "Открытая информация",
    "internal": "Для внутреннего использования",
    "confidential": "Конфиденциальная",
    "secret": "Секретная / критичная",
    "unknown": "Класс не определён",
}
_SENSITIVITY_ALIASES = {
    "открыт": "public", "публич": "public", "public": "public", "unclassified": "public",
    "внутрен": "internal", "служебн": "internal", "дсп": "internal", "internal": "internal",
    "конфиденц": "confidential", "коммерческ": "confidential", "персональн": "confidential",
    "confidential": "confidential", "private": "confidential", "pii": "confidential",
    "секрет": "secret", "особой важности": "secret", "критич": "secret",
    "secret": "secret", "top_secret": "secret", "restricted": "secret",
}


class ProvenanceAction(str, Enum):
    """Действие над объектом, из которого строится цепочка происхождения."""

    CREATE = "create"
    READ = "read"
    WRITE = "write"
    COPY = "copy"
    MOVE = "move"
    RENAME = "rename"
    ARCHIVE = "archive"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    UPLOAD = "upload"
    SEND = "send"
    DELETE = "delete"
    EXECUTE = "execute"
    UNKNOWN = "unknown"

    @property
    def is_external_flow(self) -> bool:
        """Действие выводит данные за пределы контролируемого периметра."""
        return self in {ProvenanceAction.UPLOAD, ProvenanceAction.SEND}

    @property
    def is_data_movement(self) -> bool:
        return self in {
            ProvenanceAction.COPY, ProvenanceAction.MOVE, ProvenanceAction.RENAME,
            ProvenanceAction.ARCHIVE, ProvenanceAction.UPLOAD, ProvenanceAction.SEND,
        }

    @classmethod
    def from_value(cls, value: Any, default: ProvenanceAction | None = None) -> ProvenanceAction:
        """Сопоставить произвольное строковое действие с каноническим."""
        if isinstance(value, cls):
            return value
        if value is None:
            return default or cls.UNKNOWN
        text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        if not text:
            return default or cls.UNKNOWN
        for action in cls:
            if action.value == text:
                return action
        # Wazuh/Sysmon/ECS-совместимые варианты
        if text in {"create", "created", "creation", "file_created", "new_file"}:
            return cls.CREATE
        if text in {"read", "readfile", "file_read", "access", "open"}:
            return cls.READ
        if text in {"write", "writefile", "file_write", "modify", "modified", "edit"}:
            return cls.WRITE
        if text in {"copy", "copied", "file_copy", "duplicate"}:
            return cls.COPY
        if text in {"move", "moved", "file_move", "rename", "renamed", "file_rename"}:
            return cls.RENAME if "name" in text else cls.MOVE
        if text in {"archive", "compress", "compress_file", "zip", "rar", "tar"}:
            return cls.ARCHIVE
        if text in {"encrypt", "encrypted", "encryption"}:
            return cls.ENCRYPT
        if text in {"decrypt", "decrypted", "decryption"}:
            return cls.DECRYPT
        if text in {"upload", "uploaded", "upload_file", "http_put"}:
            return cls.UPLOAD
        if text in {"send", "sent", "email", "email_send", "http_post", "post", "exfil", "transfer"}:
            return cls.SEND
        if text in {"delete", "deleted", "remove", "removed", "unlink"}:
            return cls.DELETE
        if text in {"execute", "exec", "launch", "process_create", "start", "run"}:
            return cls.EXECUTE
        return default or cls.UNKNOWN


class EntityKind(str, Enum):
    """Типы узлов графа происхождения."""

    FILE = "file"
    PROCESS = "process"
    USER = "user"
    HOST = "host"
    ENDPOINT = "endpoint"
    URL = "url"


class Severity(str, Enum):
    """Уровень риска/критичности."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @classmethod
    def from_score(cls, score: float, thresholds: dict[str, float] | None = None) -> Severity:
        """Определить уровень риска по числовой оценке и порогам конфигурации."""
        th = thresholds or {"medium": 0.3, "high": 0.6, "critical": 0.85}
        if score >= th.get("critical", 0.85):
            return cls.CRITICAL
        if score >= th.get("high", 0.6):
            return cls.HIGH
        if score >= th.get("medium", 0.3):
            return cls.MEDIUM
        return cls.LOW

    @classmethod
    def from_value(cls, value: Any, default: Severity | None = None) -> Severity:
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        aliases = {
            "низкий": "low", "инфо": "low", "info": "low", "informational": "low",
            "средний": "medium", "умеренный": "medium", "warning": "medium",
            "высокий": "high", "error": "high",
            "критический": "critical", "критичный": "critical", "fatal": "critical",
        }
        if text in aliases:
            return cls(aliases[text])
        for severity in cls:
            if severity.value == text:
                return severity
        return default or cls.LOW


class PolicyDecision(str, Enum):
    """Итоговое решение по событию после применения политик."""

    ALLOW = "allow"
    TAG = "tag"
    ALERT = "alert"
    MASK = "mask"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "tag": 1, "alert": 2, "mask": 3, "block": 4}[self.value]

    @classmethod
    def from_value(cls, value: Any, default: PolicyDecision | None = None) -> PolicyDecision:
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        for decision in cls:
            if decision.value == text:
                return decision
        return default or cls.ALLOW


class ActionType(str, Enum):
    """Действия, выполняемые модулем применения политик."""

    ALERT = "alert"
    MASK_FIELD = "mask_field"
    BLOCK = "block"
    TAG = "tag"
    NOTIFY = "notify"
    QUARANTINE = "quarantine"

    @classmethod
    def from_value(cls, value: Any) -> ActionType:
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        aliases = {
            "mask": "mask_field", "masking": "mask_field", "redact": "mask_field",
            "alerting": "alert", "block_process": "block", "tagging": "tag",
        }
        text = aliases.get(text, text)
        for action in cls:
            if action.value == text:
                return action
        raise ValueError(f"Неизвестный тип действия политики: {value!r}")


class ActionStatus(str, Enum):
    """Статус выполнения действия."""

    EXECUTED = "executed"
    SIMULATED = "simulated"
    SKIPPED = "skipped"
    FAILED = "failed"

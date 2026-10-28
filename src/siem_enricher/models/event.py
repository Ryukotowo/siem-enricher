"""Каноническая модель события SIEM."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from siem_enricher.models.enums import ProvenanceAction

_WINDOWS_HINT_CHARS = ("\\", ":\\")


def utcnow() -> datetime:
    """Текущее время в UTC с часовым поясом."""
    return datetime.now(tz=timezone.utc)


def parse_timestamp(value: Any, default: datetime | None = None) -> datetime:
    """Разобрать отметку времени из строки (ISO 8601), числа (epoch) или даты."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # миллисекунды
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                        "%d/%m/%Y %H:%M:%S", "%b %d %H:%M:%S"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return default or utcnow()
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return default or utcnow()


def isoformat(value: datetime | None) -> str | None:
    """Сериализация времени в ISO 8601 с суффиксом ``Z``."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def split_path(path: str) -> tuple[str, str, str]:
    """Разложить путь на (каталог, имя файла, расширение)."""
    if not path:
        return "", "", ""
    is_windows = any(hint in path for hint in _WINDOWS_HINT_CHARS)
    pure = PureWindowsPath(path) if is_windows else PurePosixPath(path)
    name = pure.name
    directory = str(pure.parent) if str(pure.parent) not in {"", "."} else ""
    extension = ""
    if "." in name[1:]:
        extension = "." + name.rsplit(".", 1)[1]
    return directory, name, extension


@dataclass(slots=True)
class FileRef:
    """Ссылка на файл, извлечённая из события."""

    path: str
    name: str = ""
    extension: str = ""
    directory: str = ""
    action: ProvenanceAction = ProvenanceAction.UNKNOWN
    size_bytes: int | None = None
    sha256: str | None = None
    source_field: str | None = None
    is_embedded: bool = False

    def __post_init__(self) -> None:
        if not self.name or not self.directory:
            directory, name, extension = split_path(self.path)
            self.name = self.name or name
            self.directory = self.directory or directory
            self.extension = self.extension or extension

    @property
    def key(self) -> str:
        """Нормализованный ключ файла для графа происхождения."""
        return self.path.replace("/", "\\").rstrip("\\").lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "extension": self.extension,
            "directory": self.directory,
            "action": self.action.value,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "source_field": self.source_field,
            "is_embedded": self.is_embedded,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FileRef:
        return cls(
            path=str(data.get("path", "")),
            name=str(data.get("name", "") or ""),
            extension=str(data.get("extension", "") or ""),
            directory=str(data.get("directory", "") or ""),
            action=ProvenanceAction.from_value(data.get("action")),
            size_bytes=data.get("size_bytes"),
            sha256=data.get("sha256"),
            source_field=data.get("source_field"),
            is_embedded=bool(data.get("is_embedded", False)),
        )


@dataclass(slots=True)
class ProcessInfo:
    """Сведения о процессе-источнике события."""

    name: str
    path: str | None = None
    pid: int | None = None
    cmdline: str | None = None
    parent_name: str | None = None
    parent_path: str | None = None
    integrity_level: str | None = None
    user: str | None = None

    @property
    def key(self) -> str:
        """Ключ процесса для графа происхождения."""
        return f"{self.name}|{self.pid}".lower() if self.pid else self.name.lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "pid": self.pid,
            "cmdline": self.cmdline,
            "parent_name": self.parent_name,
            "parent_path": self.parent_path,
            "integrity_level": self.integrity_level,
            "user": self.user,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProcessInfo | None:
        name = data.get("name")
        if not name:
            return None
        pid = data.get("pid")
        try:
            pid = int(pid) if pid is not None else None
        except (TypeError, ValueError):
            pid = None
        return cls(
            name=str(name),
            path=data.get("path"),
            pid=pid,
            cmdline=data.get("cmdline"),
            parent_name=data.get("parent_name"),
            parent_path=data.get("parent_path"),
            integrity_level=data.get("integrity_level"),
            user=data.get("user"),
        )


@dataclass(slots=True)
class UserInfo:
    """Сведения о пользователе события."""

    name: str
    domain: str | None = None
    is_privileged: bool = False

    @property
    def key(self) -> str:
        return f"{self.domain}\\{self.name}".lower() if self.domain else self.name.lower()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "domain": self.domain, "is_privileged": self.is_privileged}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UserInfo | None:
        name = data.get("name")
        if not name:
            return None
        return cls(
            name=str(name),
            domain=data.get("domain"),
            is_privileged=bool(data.get("is_privileged", False)),
        )


@dataclass(slots=True)
class RemoteEndpoint:
    """Внешний/сетевой адрес, фигурирующий в событии."""

    ip: str | None = None
    port: int | None = None
    url: str | None = None
    domain: str | None = None
    direction: str | None = None  # inbound | outbound | unknown
    is_external: bool = False

    @property
    def key(self) -> str:
        return (self.url or self.domain or self.ip or "unknown").lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "url": self.url,
            "domain": self.domain,
            "direction": self.direction,
            "is_external": self.is_external,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RemoteEndpoint | None:
        if not data:
            return None
        endpoint = cls(
            ip=data.get("ip"),
            url=data.get("url"),
            domain=data.get("domain"),
            direction=data.get("direction"),
            is_external=bool(data.get("is_external", False)),
        )
        port = data.get("port")
        try:
            endpoint.port = int(port) if port is not None else None
        except (TypeError, ValueError):
            endpoint.port = None
        return endpoint


@dataclass(slots=True)
class RuleRef:
    """Ссылка на правило SIEM, породившее событие."""

    id: str | None = None
    description: str | None = None
    level: int | None = None
    mitre_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "level": self.level,
            "mitre_ids": list(self.mitre_ids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RuleRef | None:
        if not data:
            return None
        level = data.get("level")
        try:
            level = int(level) if level is not None else None
        except (TypeError, ValueError):
            level = None
        mitre = data.get("mitre_ids") or []
        if isinstance(mitre, str):
            mitre = [mitre]
        return cls(
            id=str(data["id"]) if data.get("id") is not None else None,
            description=data.get("description"),
            level=level,
            mitre_ids=[str(m) for m in mitre],
        )


@dataclass(slots=True)
class NormalizedEvent:
    """Событие SIEM, приведённое к каноническому виду."""

    event_id: str
    timestamp: datetime
    source: str
    action: ProvenanceAction = ProvenanceAction.UNKNOWN
    host: str | None = None
    user: UserInfo | None = None
    process: ProcessInfo | None = None
    files: list[FileRef] = field(default_factory=list)
    remote: RemoteEndpoint | None = None
    rule: RuleRef | None = None
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def primary_file(self) -> FileRef | None:
        return self.files[0] if self.files else None

    @property
    def file_paths(self) -> list[str]:
        return [f.path for f in self.files]

    @property
    def actor_key(self) -> str:
        """Ключ субъекта действия: процесс важнее пользователя."""
        if self.process is not None:
            return f"process:{self.process.key}"
        if self.user is not None:
            return f"user:{self.user.key}"
        return "user:unknown"

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": isoformat(self.timestamp),
            "source": self.source,
            "action": self.action.value,
            "host": self.host,
            "user": self.user.to_dict() if self.user else None,
            "process": self.process.to_dict() if self.process else None,
            "files": [f.to_dict() for f in self.files],
            "remote": self.remote.to_dict() if self.remote else None,
            "rule": self.rule.to_dict() if self.rule else None,
            "tags": list(self.tags),
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], source: str | None = None) -> NormalizedEvent:
        """Восстановить событие из канонического представления (обратная операция к to_dict)."""
        return cls(
            event_id=str(data.get("event_id") or uuid.uuid4()),
            timestamp=parse_timestamp(data.get("timestamp")),
            source=str(source or data.get("source") or "unknown"),
            action=ProvenanceAction.from_value(data.get("action")),
            host=data.get("host"),
            user=UserInfo.from_dict(data["user"]) if data.get("user") else None,
            process=ProcessInfo.from_dict(data["process"]) if data.get("process") else None,
            files=[FileRef.from_dict(f) for f in data.get("files", []) if isinstance(f, Mapping)],
            remote=RemoteEndpoint.from_dict(data["remote"]) if data.get("remote") else None,
            rule=RuleRef.from_dict(data["rule"]) if data.get("rule") else None,
            tags=list(data.get("tags") or []),
            raw=dict(data.get("raw") or {}),
        )

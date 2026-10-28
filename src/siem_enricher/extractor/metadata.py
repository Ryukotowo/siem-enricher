"""Извлечение метаданных из события SIEM."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

from siem_enricher.config import ExtractorConfig
from siem_enricher.extractor import patterns as pat
from siem_enricher.models.enums import ProvenanceAction
from siem_enricher.models.event import (
    FileRef,
    NormalizedEvent,
    ProcessInfo,
    RemoteEndpoint,
    RuleRef,
    UserInfo,
    parse_timestamp,
    utcnow,
)

#: Канонический признак -> список имён полей SIEM (в нормализованном виде, без разделителей)
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "host_name": ("hostname", "host", "computername", "agentname", "computer", "nodename"),
    "user_name": ("username", "user", "accountname", "targetusername", "subjectusername",
                  "auditusername", "dstuser", "srcuser", "userid", "owner"),
    "user_domain": ("userdomain", "accountdomain", "targetdomainname", "subjectdomainname"),
    "process_name": ("processname", "imagename", "image", "newprocessname", "process",
                     "executable", "application", "winlogeventdataimage"),
    "parent_process_name": ("parentimagename", "parentprocessname", "parentname", "parentimage"),
    "process_pid": ("processid", "pid", "newprocessid", "processidentifier"),
    "parent_process_pid": ("parentprocessid", "parentpid", "parentprocessidentifier"),
    "process_cmdline": ("commandline", "cmdline", "processcommandline", "command"),
    "process_path": ("imagepath", "processpath", "executablepath", "processexecutable"),
    "remote_ip": ("destinationip", "destip", "dstip", "remoteip", "sourceip", "srcip",
                  "clientip", "ipaddress", "ip"),
    "remote_port": ("destinationport", "dstport", "remoteport", "sourceport", "port"),
    "url": ("url", "requesturl", "destinationurl", "uri", "requesturi", "fullurl"),
    "domain": ("queryname", "destinationhostname", "domainname", "hostname_dst", "dnsname"),
    "rule_id": ("ruleid", "signatureid", "sid", "detectionid", "alertid"),
    "rule_description": ("ruledescription", "description", "signature", "rulename", "alertname"),
    "rule_level": ("rulelevel", "level", "severity", "priority"),
    "file_size": ("size", "filesize", "targetfilesize", "contentslength"),
    "file_hash": ("hashes", "hash", "sha256", "sha256after", "sha256before", "md5", "md5after",
                  "md5before", "filehash", "imphash"),
    "action_raw": ("action", "eventtype", "operation", "activity", "syscall", "eventaction",
                   "winlogeventid"),
}

#: Сегменты пути поля, значения которых описывают сам узел/агент, а не внешнего получателя.
#: Например ``agent.ip`` — адрес агента SIEM, его нельзя считать адресом получателя данных.
LOCAL_ADDRESS_SEGMENTS = frozenset({"agent", "host", "observer", "manager", "node", "collector"})

#: Поля, значения которых описывают файл-источник (действие «чтение/переименование»)
SOURCE_FILE_KEYS = frozenset({"sourcefilename", "oldfilename", "sourcefile"})

#: Соответствие «поле с целевым файлом -> действие над файлом»
TARGET_FIELD_ACTIONS: dict[str, ProvenanceAction] = {
    "targetfilename": ProvenanceAction.CREATE,
    "newfilename": ProvenanceAction.CREATE,
    "destinationfilename": ProvenanceAction.COPY,
    "targetfile": ProvenanceAction.WRITE,
    "targetpath": ProvenanceAction.WRITE,
    "sourcefilename": ProvenanceAction.READ,
    "oldfilename": ProvenanceAction.RENAME,
    "filepath": ProvenanceAction.READ,
    "filename": ProvenanceAction.READ,
    "file_name": ProvenanceAction.READ,
    "objectname": ProvenanceAction.READ,
    "fullpath": ProvenanceAction.READ,
}


@dataclass(slots=True)
class ExtractedMetadata:
    """Метаданные, извлечённые из одного события."""

    files: list[FileRef] = field(default_factory=list)
    users: list[UserInfo] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    host: str | None = None
    remote: RemoteEndpoint | None = None
    rule: RuleRef | None = None
    action: ProvenanceAction = ProvenanceAction.UNKNOWN
    hashes: dict[str, str] = field(default_factory=dict)
    matched_fields: dict[str, list[str]] = field(default_factory=dict)
    dropped_system_paths: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": [f.to_dict() for f in self.files],
            "users": [u.to_dict() for u in self.users],
            "processes": [p.to_dict() for p in self.processes],
            "host": self.host,
            "remote": self.remote.to_dict() if self.remote else None,
            "rule": self.rule.to_dict() if self.rule else None,
            "action": self.action.value,
            "hashes": dict(self.hashes),
            "matched_fields": {k: list(v) for k, v in self.matched_fields.items()},
            "dropped_system_paths": self.dropped_system_paths,
        }


def _norm_key(key: str) -> str:
    """Нормализовать имя поля: нижний регистр без разделителей."""
    return "".join(ch for ch in key.lower() if ch.isalnum())


def _path_segments(field_path: str) -> set[str]:
    """Сегменты пути поля в нормализованном виде."""
    cleaned = field_path.replace("[", ".").replace("]", "")
    return {_norm_key(part) for part in cleaned.split(".") if part}


def _is_local_address_field(field_path: str) -> bool:
    """Относится ли поле с адресом к самому узлу/агенту, а не к получателю данных."""
    return bool(_path_segments(field_path) & LOCAL_ADDRESS_SEGMENTS)


def split_account(value: str) -> tuple[str | None, str]:
    """Разделить запись учётной записи на домен и имя."""
    text = (value or "").strip()
    if "\\" in text:
        domain, _, bare = text.rpartition("\\")
        return (domain or None), (bare or text)
    if "@" in text:
        bare, _, domain = text.partition("@")
        return (domain or None), bare
    return None, text


#: Родительские сегменты, которые определяют смысл неоднозначного ключа ``name``
NAME_CONTEXT_SEGMENTS: dict[str, frozenset[str]] = {
    "user_name": frozenset({"user", "account", "subject", "target", "owner", "winlog"}),
    "host_name": frozenset({"agent", "host", "observer", "computer", "node"}),
    "process_name": frozenset({"process", "image"}),
}

#: Родительские сегменты, которые определяют смысл неоднозначного ключа ``id``
ID_CONTEXT_SEGMENTS: dict[str, frozenset[str]] = {
    "rule_id": frozenset({"rule", "signature", "alert", "detection"}),
}


def _iter_leaves(obj: Any, prefix: str = "") -> Iterator[tuple[str, str, Any]]:
    """Обойти документ и выдать (полный путь, нормализованный ключ, значение)."""
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (Mapping, list, tuple)):
                yield from _iter_leaves(value, path)
            else:
                yield path, _norm_key(str(key)), value
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            path = f"{prefix}[{index}]"
            if isinstance(value, (Mapping, list, tuple)):
                yield from _iter_leaves(value, path)
            else:
                yield path, _norm_key(prefix.rsplit(".", 1)[-1]), value


class MetadataExtractor:
    """Извлекает сущности события: файлы, пользователей, процессы, сетевые адреса."""

    def __init__(self, config: ExtractorConfig | None = None) -> None:
        self.config = config or ExtractorConfig()
        self.aliases: dict[str, tuple[str, ...]] = {
            canonical: tuple(names) for canonical, names in FIELD_ALIASES.items()
        }
        # Пользовательские переопределения из конфигурации
        for canonical, names in (self.config.aliases or {}).items():
            if isinstance(names, str):
                names = [names]
            self.aliases[canonical] = tuple(_norm_key(n) for n in names)
        self._alias_index: dict[str, str] = {}
        for canonical, names in self.aliases.items():
            for name in names:
                self._alias_index.setdefault(name, canonical)

    def normalize(self, source: str, document: Mapping[str, Any]) -> NormalizedEvent:
        """Привести «сырое» событие SIEM к канонической модели."""
        raw = self._unwrap(document)
        meta = self.extract(raw)

        event_id = self._first(raw, ("_id", "id", "event_id", "event.id", "data.id", "document_id"))
        timestamp = self._find_timestamp(raw)
        tags = self._collect_tags(raw)

        event = NormalizedEvent(
            event_id=str(event_id) if event_id else str(uuid.uuid4()),
            timestamp=timestamp,
            source=source,
            action=meta.action,
            host=meta.host,
            user=meta.users[0] if meta.users else None,
            process=meta.processes[0] if meta.processes else None,
            files=meta.files,
            remote=meta.remote,
            rule=meta.rule,
            tags=tags,
            raw=dict(raw),
        )
        for file_ref in event.files:
            if file_ref.action is ProvenanceAction.UNKNOWN:
                file_ref.action = event.action
        return event

    def extract(self, raw: Mapping[str, Any]) -> ExtractedMetadata:
        """Извлечь метаданные из «сырого» документа."""
        meta = ExtractedMetadata()
        strong_hits: list[tuple[str, str, str]] = []   # (field_path, ключ, значение)
        weak_hits: list[tuple[str, str, str]] = []
        embedded_hits: list[tuple[str, str]] = []

        for field_path, key, value in _iter_leaves(raw):
            if value is None or isinstance(value, bool):
                continue
            text = str(value).strip()
            if not text:
                continue

            canonical = self._alias_index.get(key)
            if canonical:
                meta.matched_fields.setdefault(canonical, []).append(field_path)
                if canonical == "remote_ip" and _is_local_address_field(field_path):
                    # адрес самого агента/узла, а не внешний получатель данных
                    continue
                self._apply_alias(meta, canonical, text)
            elif key in {"name", "id"}:
                # Смысл ключей "name"/"id" определяется родительским сегментом (ECS-совместимые схемы)
                self._apply_context_key(meta, field_path, key, text)

            if key in pat.STRONG_FILE_KEYS:
                strong_hits.append((field_path, key, text))
            elif key in pat.WEAK_FILE_KEYS and self._in_file_context(field_path):
                weak_hits.append((field_path, key, text))
            elif key in pat.EMBEDDED_SCAN_KEYS and self.config.scan_embedded_paths:
                url_spans = self._url_spans(text)
                for candidate in pat.find_paths(text, limit=self.config.max_embedded_paths + 1):
                    # путь внутри URL — это адрес получателя, а не файловый объект
                    if self._inside_url(text, candidate, url_spans):
                        continue
                    embedded_hits.append((field_path, candidate))
                    if len(embedded_hits) >= self.config.max_embedded_paths:
                        break

        files: list[FileRef] = []
        file_source_keys: list[str] = []
        for field_path, key, value in strong_hits:
            action = TARGET_FIELD_ACTIONS.get(key, ProvenanceAction.UNKNOWN)
            before = len(files)
            if key in pat.PLURAL_FILE_KEYS:
                # поле содержит список путей через ; | ,
                for part in pat.split_file_list(value):
                    self._add_file(files, part, field_path=field_path, action=action,
                                   embedded=False, meta=meta)
            else:
                self._add_file(files, value, field_path=field_path, action=action,
                               embedded=False, meta=meta)
            file_source_keys.extend([key] * (len(files) - before))
        for field_path, key, value in weak_hits:
            if pat.looks_like_path(value):
                self._add_file(files, value, field_path=field_path, action=ProvenanceAction.UNKNOWN,
                               embedded=False, meta=meta)
        for field_path, value in embedded_hits:
            self._add_file(files, value, field_path=field_path, action=ProvenanceAction.UNKNOWN,
                           embedded=True, meta=meta)

        meta.files = files[: self.config.max_files_per_event]
        meta.users = meta.users[: self.config.max_users_per_event]
        if meta.action is ProvenanceAction.UNKNOWN:
            meta.action = self._infer_action(meta)

        # Явно указанное в событии действие уточняет действие над файлом
        # (например, action=copy при заполненном targetFilename),
        # но для файлов-источников сохраняется семантика чтения.
        for index, file_ref in enumerate(meta.files):
            key = file_source_keys[index] if index < len(file_source_keys) else ""
            if key in SOURCE_FILE_KEYS:
                continue
            if meta.action is not ProvenanceAction.UNKNOWN and not file_ref.is_embedded:
                file_ref.action = meta.action
            elif file_ref.action is ProvenanceAction.UNKNOWN:
                file_ref.action = meta.action
        return meta

    def _apply_alias(self, meta: ExtractedMetadata, canonical: str, text: str) -> None:
        if canonical == "host_name" and not meta.host:
            meta.host = text
        elif canonical == "user_name":
            domain, bare = split_account(text)
            if bare.lower() not in {"-", "n/a"} or not meta.users:
                user = UserInfo(name=bare, is_privileged=pat.is_privileged_user(bare))
                if all(u.name.lower() != bare.lower() for u in meta.users):
                    meta.users.append(user)
            if domain and meta.users and not meta.users[0].domain:
                meta.users[0].domain = domain
        elif canonical == "user_domain":
            if meta.users:
                meta.users[0].domain = meta.users[0].domain or text
        elif canonical in {"process_name", "process_path", "process_pid", "process_cmdline",
                           "parent_process_name", "parent_process_pid"}:
            self._apply_process(meta, canonical, text)
        elif canonical in {"remote_ip", "remote_port", "url", "domain"}:
            self._apply_remote(meta, canonical, text)
        elif canonical == "rule_id":
            meta.rule = meta.rule or RuleRef()
            meta.rule.id = meta.rule.id or text
        elif canonical == "rule_description":
            meta.rule = meta.rule or RuleRef()
            meta.rule.description = meta.rule.description or text
        elif canonical == "rule_level":
            meta.rule = meta.rule or RuleRef()
            if meta.rule.level is None:
                try:
                    meta.rule.level = int(float(text))
                except (TypeError, ValueError):
                    meta.rule.level = None
        elif canonical == "file_size":
            try:
                meta.hashes.setdefault("size", str(int(float(text))))
            except (TypeError, ValueError):
                pass
        elif canonical == "file_hash":
            for name, value in pat.find_hashes(text).items():
                meta.hashes.setdefault(name, value)
        elif canonical == "action_raw":
            if meta.action is ProvenanceAction.UNKNOWN:
                meta.action = ProvenanceAction.from_value(text)

    def _apply_context_key(
        self,
        meta: ExtractedMetadata,
        field_path: str,
        key: str,
        text: str,
    ) -> None:
        """Разобрать неоднозначный ключ (``name``/``id``) по родительскому сегменту пути."""
        segments = _path_segments(field_path)
        if key == "name":
            for canonical, markers in NAME_CONTEXT_SEGMENTS.items():
                if segments & markers:
                    if canonical == "host_name":
                        if not meta.host:
                            meta.host = text
                    else:
                        self._apply_alias(meta, canonical, text)
                    return
            return
        for canonical, markers in ID_CONTEXT_SEGMENTS.items():
            if segments & markers:
                self._apply_alias(meta, canonical, text)
                return

    def _apply_process(self, meta: ExtractedMetadata, canonical: str, text: str) -> None:
        if not meta.processes:
            meta.processes.append(ProcessInfo(name=""))
        process = meta.processes[0]
        if canonical == "process_name":
            if pat.looks_like_path(text):
                process.path = process.path or text
                basename = text.replace("/", "\\").rsplit("\\", 1)[-1]
            else:
                basename = text
            if not process.name:
                process.name = basename
            elif not process.parent_name:
                process.parent_name = basename
        elif canonical == "process_path":
            process.path = process.path or text
        elif canonical == "process_cmdline":
            process.cmdline = process.cmdline or text
        elif canonical == "process_pid":
            try:
                process.pid = process.pid or int(float(text))
            except (TypeError, ValueError):
                pass
        elif canonical == "parent_process_name":
            process.parent_name = process.parent_name or text
        elif canonical == "parent_process_pid":
            try:
                process.pid = process.pid
            except (TypeError, ValueError):
                pass
        if process.name and process.user is None and meta.users:
            process.user = meta.users[0].name

    def _apply_remote(self, meta: ExtractedMetadata, canonical: str, text: str) -> None:
        if meta.remote is None:
            meta.remote = RemoteEndpoint()
        remote = meta.remote
        if canonical == "remote_ip":
            ip = pat.find_ip(text) or (text if pat.find_ip(text) else None)
            if ip:
                remote.ip = remote.ip or ip
                if remote.direction is None:
                    remote.direction = "outbound"
        elif canonical == "remote_port":
            try:
                remote.port = remote.port or int(float(text))
            except (TypeError, ValueError):
                pass
        elif canonical == "url":
            url = pat.find_url(text)
            if url:
                remote.url = remote.url or url
                remote.direction = remote.direction or "outbound"
                domain = pat.find_domain(url)
                if domain:
                    remote.domain = remote.domain or domain
        elif canonical == "domain":
            domain = pat.find_domain(text) or (text if "." in text else None)
            if domain and not pat.find_ip(domain):
                remote.domain = remote.domain or domain
        if remote.ip and not remote.is_external and pat.is_external_ip(remote.ip):
            remote.is_external = True
        if remote.domain and not remote.ip:
            remote.is_external = True

    def _add_file(
        self,
        files: list[FileRef],
        raw_path: str,
        field_path: str,
        action: ProvenanceAction,
        embedded: bool,
        meta: ExtractedMetadata,
    ) -> None:
        path = pat.normalize_path(raw_path)
        if not path or not pat.looks_like_path(path):
            return
        if self.config.drop_system_paths and pat.is_system_path(
            path, self.config.system_path_prefixes or pat.SYSTEM_PATH_PREFIXES_DEFAULT
        ):
            meta.dropped_system_paths += 1
            return
        key = path.replace("/", "\\").lower()
        for existing in files:
            if existing.key == key:
                if existing.action is ProvenanceAction.UNKNOWN and action is not ProvenanceAction.UNKNOWN:
                    existing.action = action
                return
        hashes = pat.find_hashes(raw_path)
        files.append(
            FileRef(
                path=path,
                action=action,
                sha256=hashes.get("sha256"),
                source_field=field_path,
                is_embedded=embedded,
            )
        )

    @staticmethod
    def _url_spans(text: str) -> list[tuple[int, int]]:
        """Интервалы URL в тексте: пути внутри них не считаются файловыми объектами."""
        return [match.span() for match in pat.URL_RE.finditer(text)]

    @staticmethod
    def _inside_url(text: str, candidate: str, spans: list[tuple[int, int]]) -> bool:
        """True, если найденный путь целиком лежит внутри одного из URL."""
        if not spans:
            return False
        start = text.find(candidate)
        while start != -1:
            end = start + len(candidate)
            if any(left <= start and end <= right for left, right in spans):
                return True
            start = text.find(candidate, start + 1)
        return False

    @staticmethod
    def _in_file_context(field_path: str) -> bool:
        return bool(_path_segments(field_path) & pat.FILE_CONTEXT_SEGMENTS)

    @staticmethod
    def _infer_action(meta: ExtractedMetadata) -> ProvenanceAction:
        """Определить действие события по извлечённым сущностям."""
        for candidate in meta.files:
            if candidate.action is not ProvenanceAction.UNKNOWN:
                return candidate.action
        if meta.remote and (meta.remote.url or meta.remote.domain):
            return ProvenanceAction.SEND
        if meta.files:
            return ProvenanceAction.READ
        if meta.processes:
            return ProvenanceAction.EXECUTE
        return ProvenanceAction.UNKNOWN

    @staticmethod
    def _unwrap(document: Mapping[str, Any]) -> Mapping[str, Any]:
        """Развернуть обёртку Elasticsearch-попадания ``_source``."""
        if isinstance(document.get("_source"), Mapping):
            merged = dict(document["_source"])
            for key in ("_id", "_index"):
                if key in document:
                    merged[key] = document[key]
            return merged
        if isinstance(document.get("hit"), Mapping):  # ответ Wazuh API
            hit = document["hit"]
            if isinstance(hit.get("_source"), Mapping):
                merged = dict(hit["_source"])
                merged.setdefault("_id", hit.get("_id"))
                return merged
        return document

    @staticmethod
    def _first(raw: Mapping[str, Any], paths: Iterable[str]) -> Any:
        for path in paths:
            current: Any = raw
            for part in path.split("."):
                if isinstance(current, Mapping) and part in current:
                    current = current[part]
                else:
                    current = None
                    break
            if current not in (None, ""):
                return current
        return None

    @staticmethod
    def _find_timestamp(raw: Mapping[str, Any]):
        for path in ("@timestamp", "timestamp", "event.created", "event.time",
                     "data.win.system.systemTime", "utc_time", "time", "date"):
            value = MetadataExtractor._first(raw, (path,))
            if value:
                return parse_timestamp(value)
        return utcnow()

    @staticmethod
    def _collect_tags(raw: Mapping[str, Any]) -> list[str]:
        tags = raw.get("tags")
        result: list[str] = []
        if isinstance(tags, str):
            result.append(tags)
        elif isinstance(tags, (list, tuple)):
            result.extend(str(t) for t in tags)
        rule = raw.get("rule")
        if isinstance(rule, Mapping):
            groups = rule.get("groups") or rule.get("mitre", {}).get("id") if isinstance(rule.get("mitre"), Mapping) else rule.get("groups")
            if isinstance(groups, (list, tuple)):
                result.extend(str(g) for g in groups)
        return result

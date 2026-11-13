"""Единый журнал состояния: модель, правила и снимок конфигурации вместе.

Позволяет зафиксировать согласованное состояние средства и позже вернуть его
целиком — модель, файл правил и (по желанию) файл конфигурации.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from siem_enricher.ml.registry import ModelRegistry

HISTORY_DIR = Path("var") / "state-history"
JOURNAL_NAME = "journal.jsonl"
KEEP_ENTRIES = 20


def _now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _stamp() -> str:
    return datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")


def _hash_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()[:16]


class StateJournal:
    """История согласованных состояний средства."""

    def __init__(self, tenant: str = "default", base: Path | None = None,
                 rules_file: str | Path | None = None,
                 config_file: str | Path | None = None) -> None:
        self.tenant = tenant or "default"
        self.base = base or (Path.cwd() / "ml" / "artifacts")
        self.root = Path.cwd() / HISTORY_DIR
        self.journal = self.root / JOURNAL_NAME
        self.rules_file = Path(str(rules_file)) if rules_file else None
        self.config_file = Path(str(config_file)) if config_file else None
        self.registry = ModelRegistry(self.tenant, self.base)

    # ---------- чтение ----------

    def entries(self) -> list[dict[str, Any]]:
        if not self.journal.exists():
            return []
        result = []
        for line in self.journal.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                result.append(json.loads(line))
            except ValueError:
                continue
        return result

    def get(self, entry_id: str) -> dict[str, Any] | None:
        return next((item for item in self.entries() if item.get("id") == entry_id), None)

    # ---------- фиксация ----------

    def capture(self, *, actor: str = "panel", note: str = "") -> dict[str, Any]:
        """Сохранить текущее состояние: версия модели, правила, конфигурация."""
        self.root.mkdir(parents=True, exist_ok=True)
        entry_id = f"s{_stamp()}"
        existing = {item.get("id") for item in self.entries()}
        suffix = 1
        while entry_id in existing:
            suffix += 1
            entry_id = f"s{_stamp()}-{suffix}"

        active = self.registry.active() or {}
        entry: dict[str, Any] = {
            "id": entry_id,
            "ts": _now(),
            "tenant": self.tenant,
            "actor": actor,
            "note": note,
            "model_version": active.get("id"),
            "model_artifact": active.get("artifact"),
        }

        if self.rules_file and self.rules_file.exists():
            target = self.root / f"{entry_id}-rules.json"
            target.write_bytes(self.rules_file.read_bytes())
            entry["rules_snapshot"] = target.name
            entry["rules_hash"] = _hash_file(self.rules_file)

        if self.config_file and self.config_file.exists():
            target = self.root / f"{entry_id}-config.json"
            target.write_bytes(self.config_file.read_bytes())
            entry["config_snapshot"] = target.name
            entry["config_hash"] = _hash_file(self.config_file)

        with self.journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._prune()
        return entry

    # ---------- откат ----------

    def rollback(self, entry_id: str, *, restore_config: bool = False,
                 actor: str = "panel") -> dict[str, Any]:
        entry = self.get(entry_id)
        if entry is None:
            raise ValueError(f"состояние не найдено: {entry_id}")

        result: dict[str, Any] = {"id": entry_id, "tenant": self.tenant,
                                  "model": None, "rules": None, "config": None}

        if entry.get("model_version"):
            version = self.registry.rollback(str(entry["model_version"]), actor=actor)
            result["model"] = version["id"]

        snapshot = entry.get("rules_snapshot")
        if snapshot and self.rules_file:
            source = self.root / str(snapshot)
            if not source.exists():
                raise ValueError(f"нет снимка правил: {snapshot}")
            self.rules_file.write_bytes(source.read_bytes())
            result["rules"] = snapshot

        if restore_config and entry.get("config_snapshot") and self.config_file:
            source = self.root / str(entry["config_snapshot"])
            if not source.exists():
                raise ValueError("нет снимка конфигурации")
            self.config_file.write_bytes(source.read_bytes())
            result["config"] = entry["config_snapshot"]

        self._append_audit({"kind": "state_rollback", "to": entry_id,
                            "tenant": self.tenant, "actor": actor,
                            "restore_config": restore_config})
        return result

    # ---------- служебное ----------

    def _prune(self) -> None:
        entries = self.entries()
        if len(entries) <= KEEP_ENTRIES:
            return
        removable = entries[:-KEEP_ENTRIES]
        keep = {item.get("id") for item in entries[-KEEP_ENTRIES:]}
        self.journal.write_text(
            "\n".join(json.dumps(item, ensure_ascii=False) for item in entries if item.get("id") in keep) + "\n",
            encoding="utf-8",
        )
        for item in removable:
            for key in ("rules_snapshot", "config_snapshot"):
                name = item.get(key)
                if name:
                    (self.root / str(name)).unlink(missing_ok=True)

    def _append_audit(self, record: dict[str, Any]) -> None:
        path = Path.cwd() / "var" / "audit.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(record)
        payload.setdefault("audit_ts", _now())
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


__all__ = ["StateJournal", "HISTORY_DIR", "JOURNAL_NAME", "KEEP_ENTRIES"]

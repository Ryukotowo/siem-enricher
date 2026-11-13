"""Реестр версий модели организации: регистрация, активная версия, откат.

Версии хранятся как отдельные каталоги ``versions/<id>``, а рабочий каталог
модели наполняется жёсткими ссылками на файлы версии — байты не дублируются.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REGISTRY_NAME = "versions.json"
ACTIVE_NAME = "sensitivity_feedback"
KEEP_VERSIONS = 5


def _manifest_fingerprint(manifest: dict[str, Any]) -> str:
    """Короткий отпечаток набора файлов версии."""
    import hashlib

    payload = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()[:16]


def _now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def tenant_root(tenant: str, base: Path | None = None) -> Path:
    """Каталог артефактов организации."""
    base = base or (Path.cwd() / "ml" / "artifacts")
    return base if tenant in ("", "default") else base / tenant


MANIFEST_NAME = "manifest.json"


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(directory: Path) -> dict[str, Any]:
    """Контрольные суммы всех файлов каталога модели."""
    files = {}
    for item in sorted(directory.rglob("*")):
        if item.is_file() and item.name != MANIFEST_NAME:
            files[str(item.relative_to(directory)).replace("\\", "/")] = {
                "size": item.stat().st_size,
                "sha256": _sha256(item),
            }
    return {"files": files}


def verify_manifest(directory: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Сверить файлы каталога с манифестом."""
    if manifest is None:
        path = directory / MANIFEST_NAME
        if not path.exists():
            return {"ok": False, "reason": "нет манифеста", "mismatched": [], "missing": []}
        import json

        manifest = json.loads(path.read_text(encoding="utf-8"))

    expected = (manifest or {}).get("files") or {}
    mismatched, missing = [], []
    for name, info in expected.items():
        target = directory / name
        if not target.exists():
            missing.append(name)
            continue
        if target.stat().st_size != info.get("size") or _sha256(target) != info.get("sha256"):
            mismatched.append(name)
    return {
        "ok": not mismatched and not missing,
        "reason": "" if not mismatched and not missing else "файлы изменены или отсутствуют",
        "mismatched": mismatched,
        "missing": missing,
        "files": len(expected),
    }


class ModelRegistry:
    """История версий модели и указатель на активную."""

    def __init__(self, tenant: str = "default", base: Path | None = None) -> None:
        self.tenant = tenant or "default"
        self.root = tenant_root(self.tenant, base)
        self.path = self.root / REGISTRY_NAME

    # ---------- чтение и запись ----------

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"tenant": self.tenant, "active": None, "versions": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"tenant": self.tenant, "active": None, "versions": []}
        data.setdefault("versions", [])
        data.setdefault("active", None)
        data["tenant"] = self.tenant
        return data

    def save(self, data: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")

    # ---------- версии ----------

    def versions(self) -> list[dict[str, Any]]:
        return list(self.load().get("versions") or [])

    def active(self) -> dict[str, Any] | None:
        data = self.load()
        active_id = data.get("active")
        for version in data.get("versions") or []:
            if version.get("id") == active_id:
                return version
        return None

    def active_path(self) -> Path:
        return self.root / ACTIVE_NAME

    def register(self, source: Path, metrics: dict[str, Any], *, note: str = "",
                 actor: str = "trainer") -> dict[str, Any]:
        """Зарегистрировать новую версию и сделать её активной."""
        self.root.mkdir(parents=True, exist_ok=True)
        version_id = self._next_id()
        target = self.root / "versions" / version_id
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)

        manifest = build_manifest(target)
        (target / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        record = {
            "id": version_id,
            "manifest_fingerprint": _manifest_fingerprint(manifest),
            "created": _now(),
            "note": note,
            "actor": actor,
            "artifact": str(target.relative_to(self.root)).replace("\\", "/"),
            "metrics": metrics,
        }
        data = self.load()
        data.setdefault("versions", []).append(record)
        data["active"] = version_id
        self.save(data)
        self._materialise(target)
        self._prune(data)
        return record

    def verify(self, version_id: str | None = None) -> dict[str, Any]:
        """Проверить целостность версии (по умолчанию активной)."""
        data = self.load()
        target_version = None
        if version_id:
            target_version = next((item for item in data.get("versions") or []
                                   if item.get("id") == version_id), None)
        else:
            active_id = data.get("active")
            target_version = next((item for item in data.get("versions") or []
                                   if item.get("id") == active_id), None)
        if target_version is None:
            return {"ok": False, "reason": "версия не найдена", "version": version_id}
        directory = self.root / str(target_version["artifact"])
        result = verify_manifest(directory)
        result["version"] = target_version["id"]
        result["artifact"] = str(target_version["artifact"])
        return result

    def rollback(self, version_id: str | None = None, *, actor: str = "trainer") -> dict[str, Any]:
        """Сделать активной предыдущую или указанную версию."""
        data = self.load()
        versions = data.get("versions") or []
        if not versions:
            raise ValueError("нет зарегистрированных версий")
        if version_id in (None, "", "previous"):
            current = data.get("active")
            index = next((i for i, item in enumerate(versions) if item["id"] == current), len(versions) - 1)
            if index <= 0:
                raise ValueError("предыдущей версии нет")
            target_version = versions[index - 1]
        else:
            target_version = next((item for item in versions if item["id"] == version_id), None)
            if target_version is None:
                raise ValueError(f"версия не найдена: {version_id}")

        target = self.root / str(target_version["artifact"])
        if not target.exists():
            raise ValueError(f"каталог версии отсутствует: {target}")
        self._materialise(target)
        data["active"] = target_version["id"]
        self.save(data)
        self._append_audit({"kind": "model_rollback", "to": target_version["id"],
                            "tenant": self.tenant, "actor": actor})
        return target_version

    # ---------- служебное ----------

    def _next_id(self) -> str:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
        existing = {item.get("id") for item in self.versions()}
        candidate = f"v{stamp}"
        suffix = 1
        while candidate in existing:
            suffix += 1
            candidate = f"v{stamp}-{suffix}"
        return candidate

    def _materialise(self, source: Path) -> None:
        """Наполнить рабочий каталог жёсткими ссылками на файлы версии."""
        active = self.active_path()
        if active.exists():
            shutil.rmtree(active)
        active.mkdir(parents=True, exist_ok=True)
        for item in source.iterdir():
            if not item.is_file():
                continue
            try:
                os.link(item, active / item.name)
            except OSError:
                shutil.copy2(item, active / item.name)

    def _prune(self, data: dict[str, Any]) -> None:
        versions = data.get("versions") or []
        if len(versions) <= KEEP_VERSIONS:
            return
        active_id = data.get("active")
        removable = [item for item in versions[:-KEEP_VERSIONS] if item.get("id") != active_id]
        for item in removable:
            shutil.rmtree(self.root / str(item["artifact"]), ignore_errors=True)
        data["versions"] = [item for item in versions if item not in removable]
        self.save(data)

    def _append_audit(self, record: dict[str, Any]) -> None:
        path = Path.cwd() / "var" / "audit.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        record = dict(record)
        record.setdefault("audit_ts", _now())
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


__all__ = ["ModelRegistry", "tenant_root", "ACTIVE_NAME", "REGISTRY_NAME", "KEEP_VERSIONS"]

"""Контрольные суммы артефактов модели: манифест версии и проверка целостности."""

from __future__ import annotations

import ast
from pathlib import Path

REGISTRY = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "registry.py"

HELPER_ANCHOR = "class ModelRegistry:"
HELPER = '''MANIFEST_NAME = "manifest.json"


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
            files[str(item.relative_to(directory)).replace("\\\\", "/")] = {
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


class ModelRegistry:'''

REGISTER_OLD = '''        record = {
            "id": version_id,'''
REGISTER_NEW = '''        manifest = build_manifest(target)
        (target / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8"
        )

        record = {
            "id": version_id,
            "manifest_fingerprint": _manifest_fingerprint(manifest),'''

VERIFY_FUNC_OLD = '''    def rollback(self, version_id: str | None = None, *, actor: str = "trainer") -> dict[str, Any]:'''
VERIFY_FUNC_NEW = '''    def verify(self, version_id: str | None = None) -> dict[str, Any]:
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

    def rollback(self, version_id: str | None = None, *, actor: str = "trainer") -> dict[str, Any]:'''

FINGERPRINT_ANCHOR = "def _now() -> str:"
FINGERPRINT = '''def _manifest_fingerprint(manifest: dict[str, Any]) -> str:
    """Короткий отпечаток набора файлов версии."""
    import hashlib

    payload = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()[:16]


def _now() -> str:'''


def main() -> int:
    text = REGISTRY.read_text(encoding="utf-8")
    changed = 0
    if "def build_manifest" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("реестр: манифест и проверка")
    if "_manifest_fingerprint" not in text:
        text = text.replace(FINGERPRINT_ANCHOR, FINGERPRINT, 1)
        changed += 1
        print("реестр: отпечаток версии")
    if '"manifest_fingerprint"' not in text:
        text = text.replace(REGISTER_OLD, REGISTER_NEW, 1)
        changed += 1
        print("реестр: манифест при регистрации")
    if "    def verify(self" not in text:
        text = text.replace(VERIFY_FUNC_OLD, VERIFY_FUNC_NEW, 1)
        changed += 1
        print("реестр: метод verify()")
    REGISTRY.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Версии файла правил: снимок при перезагрузке, список и откат."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPER_ANCHOR = "def reload_model(app: Any) -> dict[str, Any]:"
HELPER = '''RULES_HISTORY_DIR = "var/rules-history"
RULES_KEEP = 10


def snapshot_rules(config: Any) -> str | None:
    """Сохранить копию файла правил перед перезагрузкой."""
    import shutil
    from datetime import UTC, datetime

    path = Path(str(getattr(config.ml, "rules_file", "") or ""))
    if not path.exists():
        return None
    history = Path.cwd() / RULES_HISTORY_DIR
    history.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    target = history / f"rules-{stamp}.json"
    shutil.copy2(path, target)
    saved = sorted(history.glob("rules-*.json"))
    for old in saved[:-RULES_KEEP]:
        old.unlink(missing_ok=True)
    return target.name


def rules_versions() -> list[dict[str, Any]]:
    """Список сохранённых версий правил, новые первыми."""
    history = Path.cwd() / RULES_HISTORY_DIR
    if not history.exists():
        return []
    items = []
    for path in sorted(history.glob("rules-*.json"), reverse=True):
        items.append({"name": path.name, "size": path.stat().st_size})
    return items


def rollback_rules(config: Any, name: str) -> dict[str, Any]:
    """Вернуть файл правил из сохранённой версии."""
    import shutil

    history = Path.cwd() / RULES_HISTORY_DIR
    source = history / Path(name).name
    target = Path(str(getattr(config.ml, "rules_file", "") or ""))
    if not source.exists():
        return {"ok": False, "error": f"нет версии {name}"}
    if not target.parent.exists():
        return {"ok": False, "error": f"нет каталога {target.parent}"}
    shutil.copy2(source, target)
    return {"ok": True, "rules": str(target), "from": source.name}


def reload_model(app: Any) -> dict[str, Any]:'''

ROUTE_ANCHOR = '    @app.post("/ui/model/reload", include_in_schema=False)'
ROUTE = '''    @app.get("/ui/rules/versions", include_in_schema=False)
    async def panel_rules_versions(request: Request) -> Any:
        return JSONResponse({"versions": rules_versions()})

    @app.post("/ui/rules/rollback", include_in_schema=False)
    async def panel_rules_rollback(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        name = str((payload or {}).get("version") or "")
        result = rollback_rules(request.app.state.config, name)
        if not result.get("ok"):
            return JSONResponse(result, status_code=400)
        reloaded = reload_rules(request.app)
        result["reload"] = reloaded
        _audit(request.app, {"kind": "rules_rollback", "key": "config/rules.json",
                             "from": "-", "to": name})
        return JSONResponse(result)

'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if "def snapshot_rules" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("панель: снимки и откат правил")
    if "/ui/rules/versions" not in text:
        text = text.replace(ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR, 1)
        changed += 1
        print("панель: маршруты версий правил")
    if "snapshot_rules(app.state.config)" not in text:
        old = '''    fresh = build_classifier(config.ml, None, labels_path=config.labels_path)
    pipeline.classifier = fresh
    directory_rules = getattr(getattr(fresh, "rules", fresh), "directory_rules", None)'''
        new = '''    snapshot_rules(config)
    fresh = build_classifier(config.ml, None, labels_path=config.labels_path)
    pipeline.classifier = fresh
    directory_rules = getattr(getattr(fresh, "rules", fresh), "directory_rules", None)'''
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print("панель: снимок правил перед перезагрузкой")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

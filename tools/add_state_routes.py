"""Маршруты журнала состояния в панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPER_ANCHOR = "def reload_model(app: Any) -> dict[str, Any]:"
HELPER = '''def _state_journal(config: Any) -> Any:
    from siem_enricher.ml.state import StateJournal

    return StateJournal(
        tenant=current_tenant(config),
        base=Path.cwd() / "ml" / "artifacts",
        rules_file=Path(str(getattr(config.ml, "rules_file", "") or "")),
        config_file=Path.cwd() / "config" / "config.local.json",
    )


def capture_state(app: Any, note: str = "") -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    entry = _state_journal(config).capture(
        actor=str(getattr(app.state, "audit_actor", "panel")), note=note
    )
    return {"ok": True, "state": entry}


def state_history(app: Any) -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"states": []}
    return {"states": _state_journal(config).entries()}


def rollback_state(app: Any, entry_id: str, restore_config: bool = False) -> dict[str, Any]:
    config = getattr(app.state, "config", None)
    if config is None:
        return {"ok": False, "error": "нет конфигурации"}
    journal = _state_journal(config)
    try:
        result = journal.rollback(entry_id, restore_config=restore_config,
                                 actor=str(getattr(app.state, "audit_actor", "panel")))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    reloaded = reload_model(app)
    result["reload"] = reloaded
    _audit(app, {"kind": "state_rollback", "key": "ml/state", "from": "-", "to": entry_id})
    return {"ok": True, "result": result}


def reload_model(app: Any) -> dict[str, Any]:'''

ROUTE_ANCHOR = '    @app.post("/ui/model/reload", include_in_schema=False)'
ROUTE = '''    @app.get("/ui/state", include_in_schema=False)
    async def panel_state_list(request: Request) -> Any:
        return JSONResponse(state_history(request.app))

    @app.post("/ui/state/capture", include_in_schema=False)
    async def panel_state_capture(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        return JSONResponse(capture_state(request.app, str((payload or {}).get("note") or "")))

    @app.post("/ui/state/rollback", include_in_schema=False)
    async def panel_state_rollback(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        entry_id = str((payload or {}).get("state") or "")
        restore = bool((payload or {}).get("with_config"))
        result = rollback_state(request.app, entry_id, restore)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)

'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if "def capture_state" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("панель: работа с журналом состояния")
    if "/ui/state/capture" not in text:
        text = text.replace(ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR, 1)
        changed += 1
        print("панель: маршруты журнала состояния")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

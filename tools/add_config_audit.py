"""Аудит изменений конфигурации: запись в журнал и просмотр в панели."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
AUDIT = ROOT / "src" / "siem_enricher" / "audit.py"

AUDIT_FLUSH = '''    def flush(self) -> None:
        """Сбросить буфер на диск (для важных записей вроде изменений настроек)."""
        if self.path is None:
            return
        with _LOCK:
            try:
                _flush_path(self.path)
            except OSError:
                pass

    def write(self, record: Mapping[str, Any]) -> None:'''

HELPERS = '''def _audit_logger(app: Any):
    """Логгер аудита, привязанный к пути из конфигурации."""
    from siem_enricher.audit import AuditLogger

    config = getattr(app.state, "config", None)
    path = getattr(config, "audit_log_path", None)
    if path is None:
        return None
    logger = getattr(app.state, "config_audit", None)
    if logger is None or logger.path != path:
        logger = AuditLogger(path)
        app.state.config_audit = logger
    return logger


def _audit(app: Any, record: dict[str, Any]) -> None:
    """Записать изменение конфигурации в журнал аудита."""
    logger = _audit_logger(app)
    if logger is None:
        return
    payload = dict(record)
    payload.setdefault("kind", "config_change")
    payload.setdefault("actor", getattr(app.state, "audit_actor", "panel"))
    try:
        logger.write(payload)
        logger.flush()
    except Exception:  # noqa: BLE001 - аудит не должен ломать изменения
        pass


def read_audit_tail(app: Any, limit: int = 40) -> list[dict[str, Any]]:
    """Последние изменения конфигурации из журнала."""
    import json
    from pathlib import Path as _Path

    config = getattr(app.state, "config", None)
    path = getattr(config, "audit_log_path", None)
    if path is None or not _Path(path).exists():
        return []
    records: list[dict[str, Any]] = []
    for line in _Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if str(item.get("kind", "")).endswith("change"):
            records.append(item)
    return records[-limit:][::-1]


def apply_rules('''

APPLY_RULES_TAIL_OLD = '''        rule.enabled = bool(enabled)
        applied.append(str(rule_id))
    return applied, errors'''
APPLY_RULES_TAIL_NEW = '''        previous = bool(rule.enabled)
        rule.enabled = bool(enabled)
        applied.append(str(rule_id))
        if previous != rule.enabled:
            _audit(app, {"kind": "policy_rule_change", "rule": str(rule_id),
                         "from": previous, "to": rule.enabled})
    return applied, errors'''

PERSIST_OLD = '''    if applied:
        persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)})'''
PERSIST_NEW = '''    if applied:
        persist_settings(merged, {rule["id"]: rule["enabled"] for rule in read_rules(app)})
        for key in merged:
            if key in current and str(current[key]) != str(merged[key]):
                _audit(app, {"kind": "config_change", "key": key,
                             "from": current[key], "to": merged[key]})'''

ROUTE_ANCHOR = '    @app.get("/ui/config", include_in_schema=False)'
ROUTE = '''    @app.get("/ui/audit", include_in_schema=False)
    async def panel_audit(request: Request, limit: int = 40) -> Any:
        return JSONResponse({"records": read_audit_tail(request.app, limit)})

'''

ACTOR_ANCHOR = '''        restore_settings(request.app)'''
ACTOR_NEW = '''        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        restore_settings(request.app)'''


def main() -> int:
    audit_text = AUDIT.read_text(encoding="utf-8")
    if "def flush(self) -> None:" not in audit_text:
        old = "    def write(self, record: Mapping[str, Any]) -> None:"
        if old not in audit_text:
            print("!! не найден write в audit.py")
            return 1
        audit_text = audit_text.replace(old, "    " + AUDIT_FLUSH, 1)
        AUDIT.write_text(audit_text, encoding="utf-8")
        ast.parse(audit_text)
        print("audit.py: добавлен flush()")

    text = PANEL.read_text(encoding="utf-8")
    if "_audit(" in text:
        print("аудит уже подключён")
        return 0
    pairs = [
        ("def apply_rules(", HELPERS),
        (APPLY_RULES_TAIL_OLD, APPLY_RULES_TAIL_NEW),
        (PERSIST_OLD, PERSIST_NEW),
        (ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR),
        (ACTOR_ANCHOR, ACTOR_NEW),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:48]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("panel.py: аудит подключён")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Метки аналитика: подтверждение инцидента и ложное срабатывание."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPERS = '''LABELS_FILE = "var/labels/analyst_labels.jsonl"
LABEL_VALUES = {"confirmed": "инцидент подтверждён", "false_positive": "ложное срабатывание"}


def _labels_path() -> Any:
    from pathlib import Path as _Path

    path = _Path.cwd() / LABELS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def save_label(app: Any, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Сохранить оценку аналитика по событию."""
    import json
    from datetime import UTC, datetime

    event_id = str(payload.get("event_id") or "").strip()
    label = str(payload.get("label") or "").strip()
    errors: list[str] = []
    if not event_id:
        errors.append("не указан идентификатор события")
    if label not in LABEL_VALUES:
        errors.append("метка должна быть confirmed или false_positive")
    if errors:
        return None, errors

    record = {
        "event_id": event_id,
        "label": label,
        "comment": str(payload.get("comment") or "").strip()[:500],
        "file": str(payload.get("file") or ""),
        "decision": str(payload.get("decision") or ""),
        "risk": payload.get("risk"),
        "actor": str(getattr(app.state, "audit_actor", "analyst")),
        "ts": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
    }
    with _labels_path().open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\\n")
    return record, []


def read_labels(app: Any, limit: int = 200) -> dict[str, Any]:
    """Последние метки и сводка по ним."""
    import json

    path = _labels_path()
    records: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    latest: dict[str, dict[str, Any]] = {}
    for item in records:
        latest[str(item.get("event_id"))] = item
    counts = {"confirmed": 0, "false_positive": 0}
    for item in latest.values():
        key = str(item.get("label"))
        if key in counts:
            counts[key] += 1
    return {"records": records[-limit:][::-1], "latest": latest, "counts": counts}


def apply_rules('''

ROUTES_ANCHOR = '    @app.get("/ui/audit", include_in_schema=False)'
ROUTES = '''    @app.post("/ui/label", include_in_schema=False)
    async def panel_label(request: Request) -> Any:
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"errors": ["некорректный JSON"]}, status_code=400)
        record, errors = save_label(request.app, payload)
        if errors:
            return JSONResponse({"errors": errors}, status_code=400)
        return JSONResponse({"record": record, "counts": read_labels(request.app)["counts"]})

    @app.get("/ui/labels", include_in_schema=False)
    async def panel_labels(request: Request, limit: int = 200) -> Any:
        data = read_labels(request.app, limit)
        return JSONResponse({"records": data["records"], "counts": data["counts"]})

'''

JS_FUNCS = '''let LABELS = new Map();

function labelBadge(event) {
  const label = LABELS.get(event.event_id);
  if (!label) return '';
  const text = label.label === 'confirmed' ? 'подтверждён' : 'ложное срабатывание';
  const color = label.label === 'confirmed' ? '#2E7D32' : '#B3261E';
  return `<span class="badge" style="background:#EEF1F6;color:${color}">${text}</span>`;
}

function labelBlock(event) {
  const label = LABELS.get(event.event_id);
  const comment = label && label.comment ? label.comment : '';
  return `<div class="row"><div class="k">оценка аналитика ${labelBadge(event)}</div>
    <div class="v">
      <input id="label-comment" placeholder="комментарий (необязательно)" value="${comment.replaceAll('"', '&quot;')}"
             style="width:100%;padding:5px 8px;border:1px solid #DCE3EE;border-radius:6px;font-size:12px">
      <div style="margin-top:6px;display:flex;gap:8px">
        <button class="chain-btn" onclick="labelEvent('${event.event_id}', 'confirmed')">подтвердить</button>
        <button class="chain-btn" onclick="labelEvent('${event.event_id}', 'false_positive')">ложное</button>
      </div>
      <div id="label-result" class="path" style="margin-top:4px"></div>
    </div></div>`;
}

async function loadLabels() {
  try {
    const response = await fetch('/ui/labels?limit=500', {cache: 'no-store'});
    const payload = await response.json();
    LABELS = new Map((payload.records || []).map(item => [String(item.event_id), item]));
    const counter = document.getElementById('label-counter');
    if (counter && payload.counts) {
      counter.textContent = `подтверждено ${payload.counts.confirmed}, ложных ${payload.counts.false_positive}`;
    }
    if (SELECTED) render();
  } catch (error) { /* оценки необязательны */ }
}

async function labelEvent(eventId, label) {
  const event = DATA.find(item => item.event_id === eventId) || {};
  const commentBox = document.getElementById('label-comment');
  const result = document.getElementById('label-result');
  try {
    const response = await fetch('/ui/label', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_id: eventId, label, comment: commentBox ? commentBox.value : '',
                            file: event.file, decision: event.decision, risk: event.risk})
    });
    const payload = await response.json();
    if (!response.ok) throw new Error((payload.errors || []).join('; '));
    if (result) result.textContent = 'сохранено: ' + (label === 'confirmed' ? 'инцидент подтверждён' : 'ложное срабатывание');
    await loadLabels();
    render();
  } catch (error) {
    if (result) result.textContent = 'не сохранено: ' + error.message;
  }
}

function select('''

TEMPLATE_HOOK_OLD = "  ${siemLink(event)}"
TEMPLATE_HOOK_NEW = "  ${siemLink(event)}\n  ${labelBlock(event)}"

LOAD_CALL_OLD = "loadPanelMeta();"
LOAD_CALL_NEW = "loadPanelMeta();\nloadLabels();"

COUNTER_OLD = '<button class="ghost" id="theme">тема</button>'
COUNTER_NEW = ('<button class="ghost" id="theme">тема</button>\n'
               '      <span class="counter" id="label-counter"></span>')


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "labelEvent" in text:
        print("метки уже есть")
        return 0
    pairs = [
        ("def apply_rules(", HELPERS),
        (ROUTES_ANCHOR, ROUTES + ROUTES_ANCHOR),
        ("function select(", JS_FUNCS),
        (TEMPLATE_HOOK_OLD, TEMPLATE_HOOK_NEW),
        (LOAD_CALL_OLD, LOAD_CALL_NEW),
        (COUNTER_OLD, COUNTER_NEW),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:50]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:48]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Демонстрационный поток в панели: запуск, остановка, разовая заливка."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

HELPER_ANCHOR = "def _state_journal(config: Any) -> Any:"
HELPER = '''DEMO_KEY = "demo_stream"


def _demo_state(app: Any) -> dict[str, Any]:
    state = getattr(app.state, DEMO_KEY, None)
    if state is None:
        state = {"running": False, "interval": 2.0, "scenario": "mixed",
                 "sent": 0, "task": None}
        setattr(app.state, DEMO_KEY, state)
    return state


def demo_fill(app: Any, count: int = 25, scenario: str = "mixed") -> dict[str, Any]:
    """Обогатить пачку сгенерированных событий и положить их в панель."""
    import sys

    tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from generate_sample_events import build_events

    pipeline = _pipeline_of(app)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}
    buffer = getattr(app.state, "panel_buffer", None)
    events = build_events(scenario=scenario, count=max(1, min(count, 500)))
    sent = 0
    for event in events:
        _, _, document = pipeline.enrich_document("demo", event)
        if buffer is not None:
            buffer.add(document)
        sent += 1
    return {"ok": True, "sent": sent, "scenario": scenario}


async def demo_start(app: Any, interval: float = 2.0, scenario: str = "mixed") -> dict[str, Any]:
    """Запустить непрерывный поток событий в фоне."""
    import asyncio
    import sys

    state = _demo_state(app)
    if state["running"]:
        return {"ok": True, "running": True, "already": True, "sent": state["sent"]}

    tools_dir = Path.cwd() / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from generate_sample_events import stream_events

    pipeline = _pipeline_of(app)
    buffer = getattr(app.state, "panel_buffer", None)
    if pipeline is None:
        return {"ok": False, "error": "сервис не запущен в режиме обработки"}

    state.update({"running": True, "interval": interval, "scenario": scenario, "sent": 0})

    async def loop() -> None:
        for event in stream_events(scenario=scenario, interval=0, repeat=0):
            if not state["running"]:
                break
            _, _, document = pipeline.enrich_document("demo", event)
            if buffer is not None:
                buffer.add(document)
            state["sent"] += 1
            await asyncio.sleep(max(0.1, interval))

    state["task"] = asyncio.create_task(loop())
    return {"ok": True, "running": True, "interval": interval, "scenario": scenario}


def demo_stop(app: Any) -> dict[str, Any]:
    state = _demo_state(app)
    state["running"] = False
    task = state.get("task")
    if task is not None:
        task.cancel()
    state["task"] = None
    return {"ok": True, "running": False, "sent": state["sent"]}


def demo_status(app: Any) -> dict[str, Any]:
    state = _demo_state(app)
    return {"running": bool(state["running"]), "interval": state["interval"],
            "scenario": state["scenario"], "sent": state["sent"]}


def _state_journal(config: Any) -> Any:'''

ROUTE_ANCHOR = '    @app.get("/ui/state", include_in_schema=False)'
ROUTE = '''    @app.get("/ui/demo", include_in_schema=False)
    async def panel_demo_status(request: Request) -> Any:
        return JSONResponse(demo_status(request.app))

    @app.post("/ui/demo/events", include_in_schema=False)
    async def panel_demo_events(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        count = int((payload or {}).get("count") or 25)
        scenario = str((payload or {}).get("scenario") or "mixed")
        return JSONResponse(demo_fill(request.app, count=count, scenario=scenario))

    @app.post("/ui/demo/start", include_in_schema=False)
    async def panel_demo_start(request: Request) -> Any:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}
        interval = float((payload or {}).get("interval") or 2.0)
        scenario = str((payload or {}).get("scenario") or "mixed")
        request.app.state.audit_actor = (request.headers.get("X-Analyst")
                                        or getattr(request.client, "host", "panel"))
        return JSONResponse(await demo_start(request.app, interval=interval, scenario=scenario))

    @app.post("/ui/demo/stop", include_in_schema=False)
    async def panel_demo_stop(request: Request) -> Any:
        return JSONResponse(demo_stop(request.app))

'''

UI_OLD = '      <button class="cancel" id="rules-reload">перечитать правила</button>'
UI_NEW = '''      <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
        <button class="cancel" id="demo-start">▶ поток</button>
        <button class="cancel" id="demo-stop">■ стоп</button>
        <button class="cancel" id="demo-fill">+25 событий</button>
        <span id="demo-status" style="font-size:12px;color:#5B6470"></span>
      </div>
      <button class="cancel" id="rules-reload">перечитать правила</button>'''

JS_OLD = "const rulesReload = document.getElementById('rules-reload');"
JS_NEW = '''const demoStart = document.getElementById('demo-start');
const demoStop = document.getElementById('demo-stop');
const demoFill = document.getElementById('demo-fill');
const demoStatus = document.getElementById('demo-status');

async function demoCall(path, body) {
  const response = await fetch(path, {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Analyst': 'panel'},
    body: JSON.stringify(body || {})});
  return response.json();
}

if (demoStart) {
  demoStart.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/start', {interval: 2, scenario: 'mixed'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'поток идёт' : (result.error || '');
  });
  demoStop.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/stop', {});
    if (demoStatus) demoStatus.textContent = 'остановлено, отправлено ' + (result.sent || 0);
  });
  demoFill.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/events', {count: 25, scenario: 'mixed'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'добавлено ' + result.sent : (result.error || '');
  });
}

const rulesReload = document.getElementById('rules-reload');'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if "def demo_fill" not in text:
        text = text.replace(HELPER_ANCHOR, HELPER, 1)
        changed += 1
        print("  демо-поток: функции")
    if "/ui/demo/start" not in text:
        text = text.replace(ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR, 1)
        changed += 1
        print("  демо-поток: маршруты")
    if "demo-start" not in text:
        text = text.replace(UI_OLD, UI_NEW, 1)
        text = text.replace(JS_OLD, JS_NEW, 1)
        changed += 1
        print("  демо-поток: кнопки")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

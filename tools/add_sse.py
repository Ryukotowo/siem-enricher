"""SSE-поток событий и индикатор живого режима в панели."""

from __future__ import annotations

import ast
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "service" / "panel.py"

CSS = """  .live { display:inline-flex; align-items:center; gap:7px; font-size:12px; color:#C7D2E5;
          margin-right:6px; }
  .live i { width:8px; height:8px; border-radius:50%; background:#3DDC84; display:inline-block;
            animation:pulse 1.6s infinite; }
  .live.off i { background:#B3261E; animation:none; }
  .live.paused i { background:#F0A500; animation:none; }
  @keyframes pulse { 0%{opacity:.35} 50%{opacity:1} 100%{opacity:.35} }
  .pending { color:#F0A500; font-size:12px; }
</style>"""

HEADER_OLD = """  <div class="stats">"""
HEADER_NEW = """  <div class="stats">
    <div class="live" id="live"><i></i><span id="live-text">поток</span></div>"""

PAUSE_ANCHOR = '      <button class="ghost" id="theme">тема</button>'
PAUSE_NEW = '      <button class="ghost" id="pause">пауза</button>\n' + PAUSE_ANCHOR

POLL_OLD = """refresh();
setInterval(refresh, 2000);"""
POLL_NEW = """let PAUSED = false, PENDING = 0;

function setLive(state) {
  const box = document.getElementById('live');
  const text = document.getElementById('live-text');
  if (!box || !text) return;
  box.classList.toggle('off', state === 'off');
  box.classList.toggle('paused', state === 'paused');
  text.textContent = state === 'live' ? 'поток' : state === 'paused' ? 'пауза' : 'нет связи';
}

function showPending() {
  const button = document.getElementById('pause');
  if (!button) return;
  button.textContent = PAUSED ? `продолжить${PENDING ? ' (' + PENDING + ')' : ''}` : 'пауза';
}

function connectStream() {
  if (!window.EventSource) { setLive('off'); return; }
  const source = new EventSource('/ui/stream');
  source.onopen = () => setLive(PAUSED ? 'paused' : 'live');
  source.onerror = () => setLive('off');
  source.onmessage = (message) => {
    let record;
    try { record = JSON.parse(message.data); } catch (error) { return; }
    if (PAUSED) { PENDING += 1; showPending(); return; }
    DATA = [record, ...DATA.filter(item => item.event_id !== record.event_id)].slice(0, 500);
    if (!SELECTED && record.decision === 'block') select(record.event_id);
    render();
  };
}

const pauseButton = document.getElementById('pause');
if (pauseButton) {
  pauseButton.addEventListener('click', () => {
    PAUSED = !PAUSED;
    if (!PAUSED) { PENDING = 0; refresh(); }
    setLive(PAUSED ? 'paused' : 'live');
    showPending();
  });
}

refresh();
connectStream();
setInterval(() => { if (!window.EventSource) refresh(); }, 15000);"""

BUFFER_OLD = """    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)"""
BUFFER_NEW = """    def __init__(self, size: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=size)
        self._subscribers: list[Any] = []

    def subscribe(self, callback: Any) -> None:
        \"\"\"Подписать получателя на новые события (SSE-поток панели).\"\"\"
        self._subscribers.append(callback)"""

ADD_OLD = """        self._items.append(record)"""
ADD_NEW = """        self._items.append(record)
        for callback in list(self._subscribers):
            try:
                callback(record)
            except Exception:  # noqa: BLE001 - подписчик не должен ломать буфер
                self._subscribers.remove(callback)"""

ROUTE_ANCHOR = """    @app.get("/ui/events", include_in_schema=False)"""
ROUTE = '''    @app.get("/ui/stream", include_in_schema=False)
    async def panel_stream(request: Request) -> Any:
        from fastapi.responses import StreamingResponse

        import asyncio
        import json

        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        buffer.subscribe(lambda record: queue.put_nowait(record))

        async def generator() -> Any:
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        record = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\\n\\n"
                        continue
                    yield "data: " + json.dumps(record, ensure_ascii=False) + "\\n\\n"
            finally:
                pass

        return StreamingResponse(generator(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

'''

ROUTE_END_ANCHOR = """    @app.get("/ui/config", include_in_schema=False)"""


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    if "/ui/stream" in text:
        print("SSE уже есть")
        return 0
    pairs = [
        ("</style>", CSS),
        (HEADER_OLD, HEADER_NEW),
        (PAUSE_ANCHOR, PAUSE_NEW),
        (POLL_OLD, POLL_NEW),
        (BUFFER_OLD, BUFFER_NEW),
        (ADD_OLD, ADD_NEW),
        (ROUTE_ANCHOR, ROUTE + ROUTE_ANCHOR),
    ]
    for old, new in pairs:
        if old not in text:
            print(f"!! не найдено: {old[:46]}")
            return 1
        text = text.replace(old, new, 1)
        print(f"патч: {old[:44]}")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

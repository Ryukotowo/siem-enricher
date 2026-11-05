"""Патч панели и сервиса: подсветка хэшей, цепочка, живой режим через FastAPI."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
APP = ROOT / "src" / "siem_enricher" / "service" / "app.py"
ROUTES = ROOT / "src" / "siem_enricher" / "service" / "routes.py"


def patch(path: Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in replacements:
        if new in text:
            print(f"  уже есть: {old[:48]}")
            continue
        if old not in text:
            print(f"  !! не найдено в {path.name}: {old[:48]}")
            continue
        text = text.replace(old, new, 1)
        print(f"  патч: {path.name}: {old[:48]}")
    path.write_text(text, encoding="utf-8")


CSS_OLD = "  code { background:#F1F3F7; border-radius:4px; padding:1px 5px; font-size:12px; }"
CSS_NEW = """  code { background:#F1F3F7; border-radius:4px; padding:1px 5px; font-size:12px; }
  .hash { display:inline-block; background:#EEF0F3; color:#5B6470; border-radius:4px;
          padding:0 6px; font-size:11px; margin-left:6px; }
  .chain-btn { border:1px solid var(--line); background:#fff; border-radius:7px; padding:5px 11px;
               font-size:12px; cursor:pointer; color:var(--accent); }
  .chain { margin-top:8px; border-left:2px solid #DCE3EE; padding-left:10px; display:none; }
  .chain.open { display:block; }
  .chain .step { font-size:12px; margin-bottom:6px; color:#2B3442; }
  .chain .step b { color:var(--navy); }
  .chain .step span { color:var(--muted); }"""

CELL_OLD = """      <td><div class="file">${e.file || '—'}</div><div class="path">${e.directory || ''}</div></td>"""
CELL_NEW = """      <td><div class="file">${e.file || '—'}${e.hash_only ? ' <span class="hash" title="имя пришло хэшем, полного имени в событии нет">хэш</span>' : ''}</div><div class="path">${e.directory || ''}</div></td>"""

DETAIL_OLD = """    <div class="row"><div class="k">идентификатор события</div><div class="v"><code>${event.event_id}</code></div></div>`;"""
DETAIL_NEW = """    <div class="row"><div class="k">происхождение</div>
      <button class="chain-btn" onclick="toggleChain(this)">показать цепочку (${(event.steps || []).length})</button>
      <div class="chain">${
        (event.steps || []).map((step, index) =>
          `<div class="step"><b>${index + 1}. ${step.action || '—'}</b> ${step.endpoint ? '→ ' + step.endpoint : ''}
           <br><span>${(step.ts || '').replace('T', ' ').slice(0, 19)} · ${step.actor || '—'}${step.direction ? ' · ' + step.direction : ''}</span></div>`
        ).join('') || '<div class="step"><span>шагов нет</span></div>'
      }${(event.endpoints || []).length ? `<div class="step"><span>внешние адреса: ${event.endpoints.join(', ')}</span></div>` : ''}</div></div>
    <div class="row"><div class="k">идентификатор события</div><div class="v"><code>${event.event_id}</code></div></div>`;"""

TOGGLE_OLD = "function select(eventId) {"
TOGGLE_NEW = """function toggleChain(button) {
  const chain = button.parentElement.querySelector('.chain');
  const open = chain.classList.toggle('open');
  button.textContent = open ? 'скрыть цепочку' : 'показать цепочку';
}
function select(eventId) {"""

APP_OLD = """    app.state.started_at = time.time()
    app.include_router(routes.router)"""
APP_NEW = """    app.state.started_at = time.time()

    from siem_enricher.service.panel import EventBuffer, register_panel

    panel_buffer = EventBuffer(500)
    if register_panel(app, panel_buffer):
        logger.info("Панель аналитика доступна по адресу /ui")
    app.include_router(routes.router)"""

ENRICH_OLD = """    _, _, document = runtime.pipeline.enrich_document(source, payload, apply_policies=apply_policies)
    return document"""
ENRICH_NEW = """    _, _, document = runtime.pipeline.enrich_document(source, payload, apply_policies=apply_policies)
    buffer = getattr(request.app.state, "panel_buffer", None)
    if buffer is not None:
        buffer.add(document)
    return document"""

BATCH_OLD = """    enriched = await runtime.enrich_documents(events, source=source, apply_policies=apply_policies)
    return {
        "results": [item.siem_document() for item in enriched],"""
BATCH_NEW = """    enriched = await runtime.enrich_documents(events, source=source, apply_policies=apply_policies)
    documents = [item.siem_document() for item in enriched]
    buffer = getattr(request.app.state, "panel_buffer", None)
    if buffer is not None:
        buffer.extend(documents)
    return {
        "results": documents,"""


def main() -> int:
    print("панель:")
    patch(PANEL, [
        (CSS_OLD, CSS_NEW),
        (CELL_OLD, CELL_NEW),
        (DETAIL_OLD, DETAIL_NEW),
        (TOGGLE_OLD, TOGGLE_NEW),
    ])
    print("сервис:")
    patch(APP, [(APP_OLD, APP_NEW)])
    patch(ROUTES, [(ENRICH_OLD, ENRICH_NEW), (BATCH_OLD, BATCH_NEW)])

    import ast
    for path in (PANEL, APP, ROUTES):
        ast.parse(path.read_text(encoding="utf-8"))
        print(f"  синтаксис ок: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

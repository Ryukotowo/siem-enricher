"""Ссылка в SIEM: вставка в карточку и файл настроек панели."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
SETTINGS = ROOT / "var" / "panel-settings.json"

TEMPLATE_ANCHOR = "  document.getElementById('detail-body').innerHTML = `"
TEMPLATE_NEW = "  document.getElementById('detail-body').innerHTML = `\n    ${siemLink(event)}"

FALLBACK_OLD = '''    if value in (None, ""):
        value = os.environ.get(f"SIEM_PANEL_{name.upper()}", default)
    return value'''
FALLBACK_NEW = '''    if value in (None, ""):
        value = os.environ.get(f"SIEM_PANEL_{name.upper()}")
    if value in (None, ""):
        try:
            stored = json.loads((Path.cwd() / "var" / "panel-settings.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = {}
        value = stored.get(name)
    return default if value in (None, "") else value'''


def main() -> int:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0
    if TEMPLATE_NEW not in text and TEMPLATE_ANCHOR in text:
        text = text.replace(TEMPLATE_ANCHOR, TEMPLATE_NEW, 1)
        changed += 1
        print("ссылка вставлена в карточку события")
    if "panel-settings.json" not in text and FALLBACK_OLD in text:
        text = text.replace(FALLBACK_OLD, FALLBACK_NEW, 1)
        changed += 1
        print("добавлено чтение var/panel-settings.json")
    if "import json" not in text.split("class EventBuffer")[0]:
        text = text.replace("from __future__ import annotations",
                            "from __future__ import annotations\n\nimport json\nfrom pathlib import Path", 1)
        changed += 1
        print("добавлены импорты")
    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)

    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps({
        "enabled": True,
        "siem_url_template": "http://localhost:7280/ui/search?indexId=siem-enriched&query=event_id:{event_id}",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"создан {SETTINGS.name}")
    print(f"изменений в panel.py: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

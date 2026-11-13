"""Демо: сценарий инцидента, разброс времени, подпись счётчика."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "tools" / "generate_sample_events.py"
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"

INCIDENT_SPECS = '''
    incident = [
        dict(action="read", target=confidential[0], process="excel", rule_id="92200",
             rule_level=6, description="Открытие зарплатной ведомости", scenario_tag="incident_read",
             ground_truth="confidential", user=USERS[0]),
        dict(action="archive", target=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip",
             source=confidential[0], process="7zip", rule_id="92400", rule_level=9,
             description="Упаковка зарплатной ведомости в архив", scenario_tag="incident_stage",
             ground_truth="confidential", user=USERS[0]),
        dict(action="copy", target=r"E:\\backup\\fin.zip",
             source=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip", process="explorer",
             rule_id="92300", rule_level=10, description="Копирование архива на съёмный носитель",
             scenario_tag="incident_usb", ground_truth="confidential", user=USERS[0]),
        dict(action="upload", target=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip",
             process="chrome", remote_ip=EXTERNAL_IPS[0], remote_url=EXTERNAL_URLS[0],
             rule_id="92500", rule_level=12, description="Отправка архива на внешний ресурс",
             scenario_tag="incident_upload", ground_truth="confidential", user=USERS[0]),
        dict(action="send", target=confidential[0], process="chrome", remote_ip=EXTERNAL_IPS[1],
             remote_url="https://mail.yandex.ru/compose", rule_id="92510", rule_level=12,
             description="Пересылка ведомости на внешнюю почту", scenario_tag="incident_mail",
             ground_truth="confidential", user=USERS[0]),
        dict(action="delete", target=r"E:\\backup\\fin.zip", process="explorer", rule_id="92700",
             rule_level=8, description="Удаление архива после отправки", scenario_tag="incident_clean",
             ground_truth="confidential", user=USERS[0]),
    ]

'''

SPECS_ANCHOR = "    return benign + exfiltration + secret_ops"
SPECS_NEW = '''    if scenario in{"incident", "attack"}:
        return incident

    return benign + exfiltration + secret_ops'''

SCENARIO_DOC = '''def _scenario_specs(scenario: str) -> list[dict[str, Any]]:
    """Описание сценариев генерации (для стенда и проверок)."""'''

NEW_SCENARIO_DOC = '''def _scenario_specs(scenario: str) -> list[dict[str, Any]]:
    """Описание сценариев генерации (для стенда и проверок).

    ``mixed`` — обычная смесь, ``incident`` — связная цепочка инцидента:
    чтение, упаковка, съёмный носитель, отправка наружу, почта, удаление.
    """'''


def patch_generator() -> None:
    text = GEN.read_text(encoding="utf-8")
    changed = 0
    if "incident = [" not in text:
        if SPECS_ANCHOR not in text:
            print("  !! не найдена точка возврата сценариев")
            return
        text = text.replace(SPECS_ANCHOR, INCIDENT_SPECS + SPECS_NEW, 1)
        changed += 1
        print("  генератор: сценарий incident")
    if "``incident``" not in text:
        text = text.replace(SCENARIO_DOC, NEW_SCENARIO_DOC, 1)
        changed += 1
    GEN.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"  генератор: изменений {changed}")


def patch_panel() -> None:
    text = PANEL.read_text(encoding="utf-8")
    changed = 0

    if "count: int | None = 25" not in text:
        text = text.replace("def demo_fill(app: Any, count: int = 25, scenario: str = \"mixed\")",
                            "def demo_fill(app: Any, count: int | None = 25, scenario: str = \"mixed\")", 1)
        text = text.replace("count=max(1, min(count, 500))", "count=(max(1, min(count, 500)) if count else None)")
        changed += 1
        print("  панель: количество может быть пустым")

    if "_spread_events" not in text:
        helper = '''def _spread_events(events: list[dict[str, Any]], minutes: float = 0.0) -> list[dict[str, Any]]:
    """Разложить события по времени назад от текущего момента."""
    from datetime import UTC, datetime, timedelta

    if not events:
        return events
    moment = datetime.now(tz=UTC).replace(microsecond=0)
    if minutes <= 0:
        minutes = len(events)
    step = timedelta(minutes=minutes / max(1, len(events)))
    start = moment - step * len(events)
    for position, event in enumerate(events, 1):
        stamp = start + step * position
        event["@timestamp"] = stamp.isoformat().replace("+00:00", "Z")
    return events


def _unique_events('''
        text = text.replace("def _unique_events(", helper, 1)
        changed += 1
        print("  панель: разброс времени")

    if "_spread_events(events" not in text:
        text = text.replace(
            "    events = _unique_events(app, build_events(scenario=scenario,\n"
            "                                             count=(max(1, min(count, 500)) if count else None)))",
            "    events = _unique_events(app, build_events(scenario=scenario,\n"
            "                                             count=(max(1, min(count, 500)) if count else None)))\n"
            "    _spread_events(events, minutes=90 if scenario not in {'incident', 'attack'} else 20)",
            1,
        )
        changed += 1
        print("  панель: заливка распределяется по времени")

    if 'id="demo-incident"' not in text:
        text = text.replace('<button class="cancel" id="demo-fill">+25 событий</button>',
                            '<button class="cancel" id="demo-fill">+25 событий</button>\n'
                            '        <button class="cancel" id="demo-incident">инцидент</button>', 1)
        changed += 1
        print("  панель: кнопка инцидента")

    if "demo-incident" not in text.split("demoFill.addEventListener")[0]:
        pass

    if "demoIncident" not in text:
        text = text.replace("const demoFill = document.getElementById('demo-fill');",
                            "const demoFill = document.getElementById('demo-fill');\n"
                            "const demoIncident = document.getElementById('demo-incident');", 1)
        text = text.replace("""  demoFill.addEventListener('click', async () => {""",
                            """  demoIncident.addEventListener('click', async () => {
    const result = await demoCall('/ui/demo/events', {scenario: 'incident'});
    if (demoStatus) demoStatus.textContent = result.ok ? 'инцидент добавлен' : (result.error || '');
  });
  demoFill.addEventListener('click', async () => {""", 1)
        changed += 1
        print("  панель: обработчик инцидента")

    if "<b id=\"c-fp\">0</b>открытых файлов" in text:
        text = text.replace("<b id=\"c-fp\">0</b>открытых файлов", "<b id=\"c-fp\">0</b>публичных объектов")
        changed += 1
        print("  панель: подпись счётчика")

    PANEL.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"  панель: изменений {changed}")


def main() -> int:
    patch_generator()
    patch_panel()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

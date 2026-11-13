"""Добавить связный сценарий incident в словарь сценариев генератора."""

from __future__ import annotations

import ast
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "tools" / "generate_sample_events.py"

INCIDENT = '''incident = [
    dict(action="read", target=confidential[0], process="excel", rule_id="92200",
         rule_level=6, description="Открытие зарплатной ведомости",
         scenario_tag="incident_read", ground_truth="confidential", user=USERS[0]),
    dict(action="archive", target=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip",
         source=confidential[0], process="7zip", rule_id="92400", rule_level=9,
         description="Упаковка зарплатной ведомости в архив",
         scenario_tag="incident_stage", ground_truth="confidential", user=USERS[0]),
    dict(action="copy", target=r"E:\\backup\\fin.zip",
         source=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip", process="explorer",
         rule_id="92300", rule_level=10,
         description="Копирование архива на съёмный носитель",
         scenario_tag="incident_usb", ground_truth="confidential", user=USERS[0]),
    dict(action="upload", target=r"C:\\Users\\a.ivanov\\AppData\\Local\\Temp\\fin.zip",
         process="chrome", remote_ip=EXTERNAL_IPS[0], remote_url=EXTERNAL_URLS[0],
         rule_id="92500", rule_level=12,
         description="Отправка архива на внешний ресурс",
         scenario_tag="incident_upload", ground_truth="confidential", user=USERS[0]),
    dict(action="send", target=confidential[0], process="chrome", remote_ip=EXTERNAL_IPS[1],
         remote_url="https://mail.yandex.ru/compose", rule_id="92510", rule_level=12,
         description="Пересылка ведомости на внешнюю почту",
         scenario_tag="incident_mail", ground_truth="confidential", user=USERS[0]),
    dict(action="delete", target=r"E:\\backup\\fin.zip", process="explorer", rule_id="92700",
         rule_level=8, description="Удаление архива после отправки",
         scenario_tag="incident_clean", ground_truth="confidential", user=USERS[0]),
]

scenarios = {
'''

ANCHOR = "scenarios = {\n"
DICT_OLD = '''scenarios = {
    "benign": benign,
    "exfiltration": exfiltration,
    "ransomware": ransomware,
    "mixed": benign + exfiltration + [mass_access] + ransomware,
}'''
DICT_NEW = '''scenarios = {
    "benign": benign,
    "exfiltration": exfiltration,
    "ransomware": ransomware,
    "incident": incident,
    "mixed": benign + exfiltration + [mass_access] + ransomware,
}'''


def main() -> int:
    text = GEN.read_text(encoding="utf-8")
    if "incident = [" in text:
        print("сценарий уже есть")
        return 0
    if ANCHOR not in text or DICT_OLD not in text:
        print("!! не найден словарь сценариев")
        return 1
    text = text.replace(ANCHOR, INCIDENT, 1)
    text = text.replace(DICT_NEW.replace("    \"incident\": incident,\n", ""), DICT_NEW, 1)
    GEN.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("сценарий incident добавлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

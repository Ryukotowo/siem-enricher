"""Контролируемый набор событий для оценки эффекта обогащения."""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

CONFIDENTIAL = [
    r"C:\HR\Зарплатная_ведомость_2025.xlsx",
    r"C:\HR\Личные_дела_сотрудников.xlsx",
    r"C:\Бухгалтерия\Финансовый_отчет_за_2025_год.xlsx",
    r"C:\Клиенты\База_клиентов_CRM_export.csv",
    r"C:\Юридический\Договор_поставки_ООО_Ромашка.docx",
]
SECRET = [r"C:\keys\id_rsa", r"C:\secrets\Пароли_от_сервисов.kdbx", r"C:\keys\Ключи_подписи_2025.pem"]
INTERNAL = [r"C:\Projects\Отчет_о_работе_2025.docx", r"C:\Общие\Регламент_информационной_безопасности.pdf"]
PUBLIC = [r"C:\Public\Публичный_пресс_релиз.docx", r"C:\Public\Шаблон_письма_клиенту.docx"]

EXTERNAL = [
    ("185.220.101.5", "https://dropbox.com/s/archive.zip"),
    ("45.133.1.93", "https://transfer.sh/upload/data.7z"),
    ("91.203.11.7", "https://mail.yandex.ru/compose"),
]
USERS = [("ivanov", False), ("petrova", False), ("sidorov", False), ("admin", True)]
HOSTS = ["pc-hr-01", "pc-acc-02", "pc-dev-03", "pc-law-04"]
PROCESSES = {
    "excel": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "word": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "explorer": r"C:\Windows\explorer.exe",
    "chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "7zip": r"C:\Program Files\7-Zip\7z.exe",
    "notepad": r"C:\Windows\System32\notepad.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
}

# (тип случая, метка, уровень правила SIEM, описание)
CASES: list[dict[str, Any]] = [
    {"kind": "benign_read_internal", "label": "benign", "level": 4, "action": "read",
     "pool": INTERNAL, "process": "word", "desc": "Открытие внутреннего документа"},
    {"kind": "benign_write_draft", "label": "benign", "level": 3, "action": "write",
     "pool": INTERNAL, "process": "notepad", "desc": "Создание черновика"},
    {"kind": "benign_read_public", "label": "benign", "level": 2, "action": "read",
     "pool": PUBLIC, "process": "word", "desc": "Чтение открытого файла"},
    # легитимная отправка открытого документа партнёру — правило SIEM реагирует
    {"kind": "benign_upload_public", "label": "benign", "level": 10, "action": "upload",
     "pool": PUBLIC, "process": "chrome", "external": True,
     "desc": "Отправка открытого пресс-релиза партнёру"},
    # легитимное резервное копирование внутренних документов
    {"kind": "benign_backup_archive", "label": "benign", "level": 10, "action": "archive",
     "pool": INTERNAL, "process": "7zip", "desc": "Архивирование документов в резервную копию"},
    # легитимное копирование открытого шаблона на съёмный носитель
    {"kind": "benign_usb_public", "label": "benign", "level": 10, "action": "copy",
     "pool": PUBLIC, "process": "explorer", "removable": True,
     "desc": "Копирование открытого шаблона на носитель"},

    {"kind": "exfil_usb_confidential", "label": "incident", "level": 4, "action": "copy",
     "pool": CONFIDENTIAL, "process": "explorer", "removable": True,
     "desc": "Копирование кадрового документа на съёмный носитель"},
    {"kind": "exfil_webmail_confidential", "label": "incident", "level": 5, "action": "upload",
     "pool": CONFIDENTIAL, "process": "chrome", "external": True,
     "desc": "Отправка финансового документа через веб-почту"},
    {"kind": "secret_read_kdbx", "label": "incident", "level": 6, "action": "read",
     "pool": SECRET, "process": "notepad", "desc": "Чтение хранилища паролей"},
    {"kind": "mass_copy_confidential_low", "label": "incident", "level": 7, "action": "copy",
     "pool": CONFIDENTIAL, "process": "powershell", "many": 8,
     "desc": "Массовое копирование документов"},
    {"kind": "staging_archive_confidential", "label": "incident", "level": 7, "action": "archive",
     "pool": CONFIDENTIAL, "process": "7zip",
     "desc": "Архивирование кадровых документов перед выносом"},

    {"kind": "exfil_upload_archive", "label": "incident", "level": 12, "action": "upload",
     "pool": CONFIDENTIAL, "process": "chrome", "external": True,
     "desc": "Загрузка архива во внешний файлообменник"},
    {"kind": "exfil_mail_finance", "label": "incident", "level": 12, "action": "send",
     "pool": CONFIDENTIAL, "process": "chrome", "external": True,
     "desc": "Отправка финансового документа по внешней почте"},
    {"kind": "ransomware_encrypt", "label": "incident", "level": 14, "action": "encrypt",
     "pool": CONFIDENTIAL, "process": "powershell", "desc": "Шифрование данных (ransomware)"},
    {"kind": "secret_read_key", "label": "incident", "level": 12, "action": "read",
     "pool": SECRET, "process": "powershell", "desc": "Чтение закрытого ключа"},
    {"kind": "usb_copy_confidential", "label": "incident", "level": 10, "action": "copy",
     "pool": CONFIDENTIAL, "process": "explorer", "removable": True,
     "desc": "Копирование кадровых документов на носитель"},
    {"kind": "mass_copy_confidential", "label": "incident", "level": 11, "action": "copy",
     "pool": CONFIDENTIAL, "process": "powershell", "many": 12,
     "desc": "Массовое копирование базы клиентов"},
]


def _event_data(case: dict[str, Any], paths: list[str], external: tuple[str, str] | None) -> dict[str, Any]:
    eventdata: dict[str, Any] = {
        "targetFilename": paths[0],
        "image": PROCESSES[case["process"]],
    }
    if len(paths) > 1:
        eventdata["targetFilenames"] = ";".join(paths)
    if external is not None:
        eventdata["destinationIp"] = external[0]
        eventdata["destinationUrl"] = external[1]
    if case.get("removable"):
        eventdata["sourceFilename"] = paths[0]
        eventdata["targetFilename"] = r"E:\Копия_архива.zip"
    if case.get("many"):
        eventdata["filesCount"] = case["many"]
    return eventdata


def build(repeat: int = 8, seed: int = 2026) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    start = datetime.now(tz=timezone.utc) - timedelta(minutes=repeat * len(CASES) + 5)
    events: list[dict[str, Any]] = []
    counter = 0
    for _ in range(repeat):
        for case in CASES:
            counter += 1
            paths = list(case["pool"])
            if case.get("many"):
                # массовое копирование: набор различных файлов одного каталога
                stem, _, ext = case["pool"][0].rpartition(".")
                paths = [f"{stem}_{index + 1}.{ext}" for index in range(case["many"])]
            path = rng.choice(case["pool"])
            user, privileged = rng.choice(USERS)
            host = rng.choice(HOSTS)
            external = rng.choice(EXTERNAL) if case.get("external") else None
            moment = start + timedelta(minutes=counter * 1.5)
            events.append({
                "id": f"{int(moment.timestamp())}.{counter:06d}",
                "@timestamp": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agent": {"id": "001", "name": host, "ip": "10.0.0.11"},
                "rule": {
                    "id": f"9{rng.randint(2200, 2999)}",
                    "level": case["level"],
                    "description": case["desc"],
                    "groups": ["sysmon", "windows", "experiment"],
                },
                "location": "EventChannel",
                "data": {
                    "action": case["action"],
                    "win": {
                        "system": {"computer": host},
                        "eventdata": {
                            "user": (f"DOMAIN\\{user}" if not privileged else f"DOMAIN\\{user}"),
                            "privileged": privileged,
                            **_event_data(case, paths if case.get("many") else [path], external),
                        },
                    },
                },
                "x_label": case["label"],
                "x_kind": case["kind"],
            })
    return events


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Набор событий для оценки эффекта обогащения")
    parser.add_argument("--repeat", type=int, default=8)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", default="var/experiment/dataset.jsonl")
    args = parser.parse_args()

    events = build(repeat=args.repeat, seed=args.seed)
    target = PROJECT_ROOT / args.out
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    incidents = sum(1 for event in events if event["x_label"] == "incident")
    alerting = sum(1 for event in events if event["rule"]["level"] >= 10)
    print(f"событий: {len(events)} (инцидентов {incidents}, легитимных {len(events) - incidents})")
    print(f"правила SIEM (level >= 10) срабатывают на: {alerting}")
    print(f"файл: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

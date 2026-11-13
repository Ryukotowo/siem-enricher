"""Генератор синтетических событий SIEM (формат алертов Wazuh/Sysmon)."""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

FILE_CATALOG: list[dict[str, str]] = [
    {"path": r"C:\HR\Зарплатная_ведомость_2025.xlsx", "label": "confidential"},
    {"path": r"C:\HR\Личные_дела_сотрудников.xlsx", "label": "confidential"},
    {"path": r"C:\HR\Паспортные_данные_сотрудников.xlsx", "label": "confidential"},
    {"path": r"\\srv-file-01\HR\Приказы_о_приеме_на_работу.docx", "label": "confidential"},
    {"path": r"C:\Бухгалтерия\Счет_фактура_№1420.docx", "label": "confidential"},
    {"path": r"C:\Бухгалтерия\Финансовый_отчет_за_2025_год.xlsx", "label": "confidential"},
    {"path": r"C:\Юридический\Договор_поставки_ООО_Ромашка.docx", "label": "confidential"},
    {"path": r"C:\Медицина\Диагнозы_пациентов_2025.xlsx", "label": "confidential"},
    {"path": r"C:\Клиенты\База_клиентов_CRM_export.csv", "label": "confidential"},
    {"path": r"C:\secrets\.env", "label": "secret"},
    {"path": r"C:\keys\id_rsa", "label": "secret"},
    {"path": r"C:\keys\Ключи_подписи_2025.pem", "label": "secret"},
    {"path": r"C:\secrets\Пароли_от_сервисов.kdbx", "label": "secret"},
    {"path": r"C:\Документы\Отчет_о_работе_2025.docx", "label": "internal"},
    {"path": r"C:\Инструкции\Инструкция_по_делопроизводству.docx", "label": "internal"},
    {"path": r"C:\Регламенты\Регламент_информационной_безопасности.pdf", "label": "internal"},
    {"path": r"C:\Документы\Служебная_записка_черновик.docx", "label": "internal"},
    {"path": r"\\srv-file-01\документы\Отчет_за_квартал.docx", "label": "internal"},
    {"path": r"C:\Public\readme.md", "label": "public"},
    {"path": r"C:\Public\Публичный_пресс_релиз.docx", "label": "public"},
    {"path": r"C:\Public\Шаблон_письма_клиенту.docx", "label": "public"},
]

CATALOG_BY_PATH = {item["path"]: item["label"] for item in FILE_CATALOG}


def _by_label(label: str) -> list[str]:
    return [item["path"] for item in FILE_CATALOG if item["label"] == label]


HOSTS = ["pc-hr-01", "pc-acc-02", "pc-dev-03", "srv-file-01"]
USERS = [
    {"name": "ivanov", "domain": "DOMAIN", "privileged": False},
    {"name": "petrova", "domain": "DOMAIN", "privileged": False},
    {"name": "admin", "domain": "DOMAIN", "privileged": True},
]
PROCESSES = {
    "excel": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "word": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "explorer": r"C:\Windows\explorer.exe",
    "chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "7zip": r"C:\Program Files\7-Zip\7z.exe",
    "notepad": r"C:\Windows\System32\notepad.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "unknown": r"C:\Users\ivanov\AppData\Local\Temp\svchost32.exe",
}
EXTERNAL_IPS = ["185.220.101.5", "45.133.1.93", "91.203.11.7"]
EXTERNAL_URLS = [
    "https://dropbox.com/s/hr_2025.zip",
    "https://transfer.sh/archive/payment_data.7z",
    "https://mail.google.com/mail/u/0/#sent",
]
REMOVABLE_PATHS = [r"E:\Копия_{name}", r"F:\backup\{name}", r"E:\temp\{name}"]


def _alert(
    *,
    timestamp: datetime,
    action: str,
    target: str | None = None,
    source: str | None = None,
    process: str = "explorer",
    host: str = "pc-hr-01",
    user: dict[str, Any] | None = None,
    remote_ip: str | None = None,
    remote_url: str | None = None,
    rule_id: str = "92000",
    rule_level: int = 8,
    description: str = "Событие файловой системы",
    event_id: str = "11",
    files: list[str] | None = None,
    scenario_tag: str = "benign",
    ground_truth: str = "internal",
    index: int = 0,
    event_number: int = 0,
) -> dict[str, Any]:
    """Собрать алерт в формате, близком к Wazuh (Sysmon-канал EventChannel)."""
    user = user or USERS[0]
    eventdata: dict[str, Any] = {
        "image": PROCESSES.get(process, process),
        "user": f"{user['domain']}\\{user['name']}",
        "utcTime": timestamp.isoformat().replace("+00:00", "Z"),
    }
    if target:
        eventdata["targetFilename"] = target
    if source:
        eventdata["sourceFilename"] = source
    if remote_ip:
        eventdata["destinationIp"] = remote_ip
        eventdata["destinationPort"] = 443
    data: dict[str, Any] = {"action": action, "win": {"system": {"computer": host, "eventID": event_id},
                                                      "eventdata": eventdata}}
    if files:
        data["files"] = [{"path": path} for path in files]
    if remote_url:
        data["win"]["eventdata"]["destinationUrl"] = remote_url

    return {
        "id": f"1700000000.{event_number:06d}",
        "@timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "agent": {"id": "001", "name": host, "ip": "10.0.0.11"},
        "manager": {"name": "wazuh-manager"},
        "rule": {"id": rule_id, "level": rule_level, "description": description,
                 "groups": ["sysmon", "windows", "siem_enricher_demo"]},
        "location": "EventChannel",
        "decoder": {"name": "windows_eventchannel"},
        "data": data,
        "full_log": f"{description}: {target or source or ''} ({action})",
        # Служебные поля генератора (не влияют на обогащение, используются для оценки качества)
        "x_scenario": scenario_tag,
        "x_ground_truth": {"sensitivity": ground_truth, "path": target or source or "",
                           "index": index},
    }


def _scenario_specs(scenario: str) -> list[dict[str, Any]]:
    """Описание событий сценария (без меток времени)."""
    confidential = _by_label("confidential")
    internal = _by_label("internal")
    public = _by_label("public")
    secret = _by_label("secret")

    benign = [
        dict(action="read", target=internal[0], process="word", rule_id="92200", rule_level=4,
             description="Открытие внутреннего документа", scenario_tag="benign_read",
             ground_truth="internal"),
        dict(action="read", target=public[0], process="notepad", rule_id="92200", rule_level=2,
             description="Чтение открытого файла", scenario_tag="benign_public",
             ground_truth="public"),
        dict(action="read", target=public[2], process="word", rule_id="92200", rule_level=2,
             description="Открытие общего шаблона", scenario_tag="benign_public",
             ground_truth="public"),
        dict(action="write", target=internal[3], process="notepad", rule_id="92201", rule_level=3,
             description="Создание черновика", scenario_tag="benign_write", ground_truth="internal"),
    ]

    exfiltration = [
        dict(action="read", target=confidential[0], process="excel", rule_id="92200", rule_level=6,
             description="Обращение к кадровому документу", scenario_tag="insider_read",
             ground_truth="confidential", user=USERS[0]),
        dict(action="read", target=confidential[1], process="excel", rule_id="92200", rule_level=6,
             description="Обращение к личным делам сотрудников", scenario_tag="insider_hr",
             ground_truth="confidential", user=USERS[0]),
        dict(action="copy", target=r"E:\Копия_Зарплатная_ведомость_2025.xlsx", source=confidential[0],
             process="explorer", rule_id="92300", rule_level=10,
             description="Копирование кадрового документа на съёмный носитель",
             scenario_tag="usb_copy", ground_truth="confidential", user=USERS[0]),
        dict(action="archive", target=r"C:\Users\ivanov\Documents\hr_2025.zip", source=confidential[0],
             process="7zip", rule_id="92400", rule_level=8,
             description="Архивирование кадровых документов", scenario_tag="staging_archive",
             ground_truth="confidential", user=USERS[0]),
        dict(action="upload", target=r"C:\Users\ivanov\Documents\hr_2025.zip", process="chrome",
             remote_ip=EXTERNAL_IPS[0], remote_url=EXTERNAL_URLS[0], rule_id="92500", rule_level=12,
             description="Загрузка архива во внешний файлообменник", scenario_tag="exfil_upload",
             ground_truth="confidential", user=USERS[0]),
        dict(action="send", target=confidential[4], process="chrome", remote_ip=EXTERNAL_IPS[2],
             remote_url="https://mail.yandex.ru/compose", rule_id="92510", rule_level=12,
             description="Отправка финансового документа по внешней почте", scenario_tag="exfil_mail",
             ground_truth="confidential", user=USERS[0]),
        dict(action="read", target=secret[0], process="notepad", rule_id="92600", rule_level=12,
             description="Доступ к файлу с секретами", scenario_tag="secret_access",
             ground_truth="secret", user=USERS[0]),
        dict(action="read", target=secret[1], process="powershell", rule_id="92600", rule_level=12,
             description="Чтение закрытого ключа", scenario_tag="secret_access",
             ground_truth="secret", user=USERS[0]),
    ]

    mass_access = dict(
        action="copy", process="powershell", rule_id="92700", rule_level=11,
        description="Массовое копирование файлов каталога", scenario_tag="mass_copy",
        ground_truth="confidential", user=USERS[0],
        files=[confidential[0], confidential[1], confidential[3], confidential[4],
               confidential[5], internal[0], internal[1], internal[2], public[0],
               public[1], confidential[8], confidential[7]],
        target=r"C:\Users\ivanov\Documents\!dump",
    )

    ransomware = [
        dict(action="encrypt", target=r"C:\Users\ivanov\Documents\Договор_поставки_ООО_Ромашка.docx.locked",
             process="unknown", rule_id="92800", rule_level=14,
             description="Шифрование файла (ransomware)", scenario_tag="ransomware",
             ground_truth="confidential", user=USERS[0]),
        dict(action="rename", target=r"C:\Users\ivanov\Documents\Финансовый_отчет.xlsx.enc",
             source=r"C:\Users\ivanov\Documents\Финансовый_отчет.xlsx", process="unknown",
             rule_id="92800", rule_level=14, description="Переименование файла с шифрованием",
             scenario_tag="ransomware", ground_truth="confidential", user=USERS[0]),
    ]

    scenarios = {
        "benign": benign,
        "exfiltration": exfiltration,
        "ransomware": ransomware,
        "mixed": benign + exfiltration + [mass_access] + ransomware,
    }
    if scenario not in scenarios:
        raise SystemExit(f"Неизвестный сценарий {scenario!r}. Доступны: {', '.join(scenarios)}")
    return scenarios[scenario]


def stream_events(
    scenario: str = "mixed",
    count: int | None = None,
    seed: int = 42,
    interval: float = 2.0,
    repeat: int = 0,
    start: datetime | None = None,
    host: str | None = None,
):
    """Отдавать события порциями с паузой — для живого потока на стенде.

    ``repeat=0`` означает бесконечный поток, ``interval`` — пауза между событиями.
    """
    import time
    from datetime import timedelta

    base = start or datetime.now(timezone.utc).replace(microsecond=0)
    attempt = 0
    while True:
        attempt += 1
        chunk = build_events(scenario=scenario, count=count, seed=seed + attempt - 1,
                             start=base, host=host)
        # следующая порция продолжает время последней, иначе события идут не по порядку
        try:
            last = max(datetime.fromisoformat(str(e["@timestamp"]).replace("Z", "+00:00"))
                       for e in chunk)
            base = last + timedelta(seconds=1)
        except (KeyError, ValueError):
            base = base + timedelta(seconds=max(1, count or 1))
        for position, event in enumerate(chunk, 1):
            # идентификатор содержит фиксированную метку времени, поэтому в потоке
            # делаем её уникальной для каждого повтора
            event["id"] = f"{1700000000 + attempt}.{position:06d}"
            if interval > 0:
                time.sleep(interval)
            yield event
        if repeat and attempt >= repeat:
            return


def build_events(
    scenario: str = "mixed",
    count: int | None = None,
    seed: int = 42,
    start: datetime | None = None,
    host: str | None = None,
) -> list[dict[str, Any]]:
    """Сгенерировать поток событий выбранного сценария."""
    rng = random.Random(seed)
    specs = _scenario_specs(scenario)
    total = count if count and count > 0 else len(specs)
    timestamp = start or datetime(2025, 3, 3, 9, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []

    for index in range(total):
        spec = dict(specs[index % len(specs)])
        user = spec.get("user") or rng.choice(USERS)
        event_host = host or rng.choice(HOSTS)
        round_number = index // len(specs)

        target = spec.get("target")
        if target and round_number:
            # Разнообразим имена файлов, сохраняя класс конфиденциальности
            stem, _, extension = target.rpartition(".")
            target = f"{stem}_{round_number}.{extension}" if extension else f"{target}_{round_number}"
        files = spec.get("files")
        if files and round_number:
            files = [f"{path[:-5]}_{round_number}.xlsx" if path.endswith(".xlsx") else f"{path}_{round_number}"
                     for path in files]

        timestamp = timestamp + timedelta(minutes=rng.randint(1, 7))
        events.append(
            _alert(
                timestamp=timestamp,
                action=spec.get("action", "read"),
                target=target,
                source=spec.get("source"),
                process=spec.get("process", "explorer"),
                host=event_host,
                user=user,
                remote_ip=spec.get("remote_ip"),
                remote_url=spec.get("remote_url"),
                rule_id=spec.get("rule_id", "92000"),
                rule_level=int(spec.get("rule_level", 8)),
                description=spec.get("description", "Событие"),
                files=files,
                scenario_tag=spec.get("scenario_tag", "benign"),
                ground_truth=spec.get("ground_truth", "internal"),
                index=index,
                event_number=index + 1,
            )
        )
    return events


def write_labels(events: list[dict[str, Any]], path: str | Path) -> int:
    """Выгрузить эталонную разметку ``путь -> класс`` для обучения модели."""
    labels: dict[str, str] = {}
    for event in events:
        ground_truth = event.get("x_ground_truth") or {}
        path_value = str(ground_truth.get("path") or "")
        if path_value:
            labels[path_value] = str(ground_truth.get("sensitivity", "internal"))
        for item in (event.get("data", {}) or {}).get("files", []) or []:
            item_path = str(item.get("path") or "")
            if item_path:
                labels.setdefault(item_path, str(ground_truth.get("sensitivity", "internal")))
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "label"])
        for item_path, label in sorted(labels.items()):
            writer.writerow([item_path, label])
    return len(labels)


def write_events(events: list[dict[str, Any]], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Генератор синтетических событий SIEM")
    parser.add_argument("--scenario", default="mixed",
                        choices=["benign", "exfiltration", "ransomware", "mixed"])
    parser.add_argument("--count", type=int, default=None, help="Число событий (по умолчанию — все шаблоны)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--host", default=None, help="Зафиксировать имя хоста агента")
    parser.add_argument("--out", default="var/generated_events.jsonl", help="Файл событий (JSONL)")
    parser.add_argument("--labels-out", default=None,
                        help="Файл эталонной разметки (CSV: path,label) для обучения модели")
    parser.add_argument("--interval", type=float, default=0.0,
                        help="пауза между событиями в секундах (0 — без пауз)")
    parser.add_argument("--repeat", type=int, default=1,
                        help="сколько раз повторить набор (0 — бесконечно)")
    parser.add_argument("--stats-only", action="store_true", help="Не писать события, только сводку")
    args = parser.parse_args(argv)

    events = build_events(scenario=args.scenario, count=args.count, seed=args.seed, host=args.host)
    if not args.stats_only:
        write_events(events, args.out)
        print(f"Записано событий: {len(events)} -> {args.out}")
    if args.labels_out:
        count = write_labels(events, args.labels_out)
        print(f"Эталонная разметка: {count} объектов -> {args.labels_out}")

    distribution: dict[str, int] = {}
    for event in events:
        tag = str(event.get("x_scenario", "unknown"))
        distribution[tag] = distribution.get(tag, 0) + 1
    print("Распределение по сценариям:")
    for tag, number in sorted(distribution.items()):
        print(f"  {tag:<20} {number}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

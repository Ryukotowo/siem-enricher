"""Генерация синтетического набора имён файлов, похожего на реальный документооборот.

Набор синтетический (шаблоны + словари), но воспроизводит типичные признаки:
русские имена с пробелами и подчёркиваниями, даты в разных форматах, номера договоров,
копии и версии, смешение языков, вложенные каталоги, служебный мусор.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "var" / "datasets" / "synth_names_1500.jsonl"
COUNT = 1500
SEED = 20261103

SURNAMES = ["Иванов", "Петров", "Сидоров", "Кузнецов", "Смирнова", "Попов", "Соколов", "Морозов",
            "Лебедев", "Козлов", "Новиков", "Егоров", "Волков", "Соловьёв", "Васильев", "Зайцев",
            "Павлов", "Семёнов", "Голубев", "Виноградов", "Богданов", "Воробьёв", "Фёдоров", "Михайлов",
            "Беляев", "Тарасов", "Белов", "Комаров", "Орлов", "Киселёв", "Макаров", "Андреев",
            "Ковалёв", "Ильин", "Гусев", "Титов", "Кудрявцев", "Баранов", "Куликов", "Алексеев"]
INITIALS = ["А.А.", "И.И.", "С.В.", "Д.В.", "М.Ю.", "Е.П.", "В.Н.", "О.С.", "Н.К.", "Т.Г."]
COMPANIES = ["ООО Ромашка", "ООО Вектор", "АО Прогресс", "ООО Северный ветер", "АО Технополис",
             "ООО Альфа-Трейд", "АО Стройинвест", "ООО Логистик Плюс", "ООО Медсервис",
             "АО Энергосбыт", "ООО Консалт Групп", "АО Ритм", "ООО Гранит", "АО Партнёр"]
DEPARTMENTS = ["отдел кадров", "бухгалтерия", "юридический отдел", "ИТ-отдел", "отдел продаж",
               "служба безопасности", "планово-экономический отдел", "канцелярия"]
MONTHS = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август",
          "сентябрь", "октябрь", "ноябрь", "декабрь"]
MONTHS_EN = ["january", "february", "march", "april", "may", "june", "july", "august",
             "september", "october", "november", "december"]

DIRS = {
    "personal": ["C:\\HR\\Личные дела", "C:\\HR\\Личные дела\\2024", "C:\\Отдел кадров\\Сотрудники",
                 "D:\\Кадры\\Личные дела", "C:\\HR\\Кандидаты"],
    "banking": ["C:\\Бухгалтерия\\Платежи", "C:\\Бухгалтерия\\Реквизиты", "C:\\Финансы\\Банк",
                "D:\\Бухгалтерия\\2025", "C:\\Бухгалтерия\\Выписки"],
    "commercial": ["C:\\Юридический\\Договоры", "C:\\Договоры\\2024", "C:\\Юридический\\Договоры\\Поставка",
                   "D:\\Контракты\\Действующие", "C:\\Отдел продаж\\Коммерческие предложения"],
    "ip": ["C:\\Projects\\Исходники", "C:\\Проекты\\Разработка", "C:\\Разработка\\Релизы",
           "D:\\Проекты\\Архив", "C:\\Projects\\Design"],
    "official_internal": ["C:\\Общие\\Регламенты", "C:\\Документы\\Приказы", "C:\\Общие\\Политики",
                          "C:\\ИТ\\Документация", "C:\\Служба безопасности\\Инструкции"],
    "public": ["C:\\Public\\Пресс-релизы", "C:\\Общие\\Шаблоны", "C:\\Public\\Публикации",
               "D:\\Обмен\\Общее", "C:\\Public\\Презентации"],
    "secret": ["C:\\keys", "C:\\Секретно\\Доступы", "C:\\ИТ\\Ключи", "D:\\Резерв\\Ключи"],
}

TEMPLATES = {
    "personal": [
        "Личное дело {surname_case} {initials}", "Анкета {surname_case} {initials}", "Копия паспорта {surname_case}",
        "СНИЛС {surname} {initials}", "Трудовой договор {surname} {initials}",
        "Заявление на отпуск {surname_case}", "Согласие на обработку ПДн {surname}",
        "Справка 2-НДФЛ {surname} {year}", "Медицинская книжка {surname_case}", "Резюме {surname_case} {initials}",
        "Список сотрудников на {date}", "Табель учёта рабочего времени {month} {year}",
        "График отпусков {year}",
    ],
    "banking": [
        "Платёжное поручение №{num} от {date}", "Выписка по счёту {month} {year}",
        "Реквизиты {company}", "Реестр платежей {date}", "Счёт на оплату №{num} от {date}",
        "Акт сверки с {company} {year}", "Банковская гарантия №{num}", "Инкассовое поручение №{num}",
        "Заявка на кредит {company} {year}",
    ],
    "commercial": [
        "Договор поставки №{num}-{year} {company}", "Спецификация к договору №{num}",
        "Коммерческое предложение {company} {year}", "Дополнительное соглашение №{num} к договору",
        "Протокол разногласий по договору №{num}", "Счёт-фактура №{num} от {date}",
        "Прайс-лист {month} {year}", "Тендерная документация {year}",
        "Расчёт стоимости {company}", "Смета проекта {company}",
    ],
    "ip": [
        "Техническое задание {project} v{ver}", "Исходный код {module} v{ver}",
        "Архитектура {project}", "Прототип интерфейса {project} v{ver}",
        "Релиз {project} {ver}", "Документация API {project}", "Схема базы данных {project}",
        "Дизайн-макет {project} {ver}", "Алгоритм {module} описание",
        "Патентная заявка {num}", "Ноу-хау описание {project}",
    ],
    "official_internal": [
        "Приказ №{num} от {date} о {topic}", "Регламент {topic}", "Инструкция по {topic}",
        "Политика информационной безопасности", "Положение о {topic}",
        "Служебная записка {surname} от {date}", "Протокол совещания {date}",
        "Отчёт о работе за {month} {year}", "План работ на {month} {year}",
        "Акт проверки от {date}", "Журнал регистрации входящих документов {year}", "Распоряжение №{num} от {date}",
    ],
    "public": [
        "Пресс-релиз {company} {month}", "Публичный отчёт {year}", "Презентация компании {year}",
        "Шаблон письма клиенту", "Шаблон коммерческого предложения", "Буклет {company}",
        "Публикация в СМИ {month} {year}", "Рекламные материалы {year}",
        "Открытые данные {year}", "README", "Лицензия", "CHANGELOG",
    ],
    "secret": [
        "Ключи сервисов", "Пароли администраторов", "Экспорт хранилища KeePass",
        "Закрытый ключ подписи", "Токены API", "Сертификат и ключ", "Доступы к прод",
    ],
}

TOPICS = ["предоставлении отпуска", "приёме на работу", "увольнении", "переводе на должность",
          "утверждении регламента", "проведении проверки", "изменении оклада", "командировке",
          "премировании", "охране труда", "резервном копировании", "доступе к системе"]
PROJECTS = ["sensor-hub", "dlp-core", "crm-light", "склад", "биллинг", "мобильное приложение",
            "портал самообслуживания", "аналитика продаж"]
MODULES = ["auth", "parser", "gateway", "reports", "sync", "billing"]
EXTS = {
    "personal": [".docx", ".docx", ".pdf", ".xlsx", ".jpg"],
    "banking": [".xlsx", ".pdf", ".docx", ".1c"],
    "commercial": [".docx", ".pdf", ".xlsx"],
    "ip": [".zip", ".py", ".md", ".pdf", ".fig", ".pptx", ".tar.gz"],
    "official_internal": [".docx", ".pdf", ".docx"],
    "public": [".docx", ".pdf", ".pptx", ".md"],
    "secret": [".kdbx", ".pem", ".txt", ".key"],
}
WEIGHTS = [("personal", 0.22), ("banking", 0.10), ("commercial", 0.18), ("ip", 0.12),
           ("official_internal", 0.26), ("public", 0.08), ("secret", 0.04)]
LEVELS = {"personal": "confidential", "banking": "confidential", "commercial": "confidential",
          "ip": "confidential", "official_internal": "internal", "public": "public",
          "secret": "secret"}



def genitive(surname: str) -> str:
    """Простая форма родительного падежа для типовых русских фамилий."""
    if surname.endswith(("ова", "ева", "ина", "ая", "ко", "их")):
        return surname
    if surname.endswith(("ов", "ев", "ин", "ын")):
        return surname + "а"
    return surname

def pick_category(rng: random.Random) -> str:
    threshold = rng.random()
    total = 0.0
    for name, weight in WEIGHTS:
        total += weight
        if threshold <= total:
            return name
    return WEIGHTS[-1][0]


def base_name(category: str, rng: random.Random) -> tuple[str, str]:
    template = rng.choice(TEMPLATES[category])
    year = rng.choice([2023, 2024, 2025, 2026])
    date = f"{rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.{year}"
    month = rng.choice(MONTHS)
    name = template.format(
        surname=rng.choice(SURNAMES),
        surname_case=genitive(rng.choice(SURNAMES)),
        initials=rng.choice(INITIALS),
        company=rng.choice(COMPANIES),
        year=year,
        date=date,
        month=month,
        num=rng.randint(10, 999),
        ver=f"{rng.randint(1, 4)}.{rng.randint(0, 9)}",
        project=rng.choice(PROJECTS),
        module=rng.choice(MODULES),
        topic=rng.choice(TOPICS),
    )
    if rng.random() < 0.12:  # иногда название по-английски
        name = rng.choice([
            f"{rng.choice(MONTHS_EN).capitalize()}_report_{year}",
            f"{rng.choice(PROJECTS)}_design_v{rng.randint(1, 3)}",
            "meeting_notes_" + date.replace(".", "-"),
            "Q%d_report_final" % rng.randint(1, 4),
            "invoice_%d" % rng.randint(100, 999),
        ])
    extension = rng.choice(EXTS[category])
    return name, extension


def add_noise(name: str, rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.10:
        name = "Копия " + name
    elif roll < 0.16:
        name = name + " (копия)"
    elif roll < 0.22:
        name = name + f" ({rng.randint(1, 3)})"
    elif roll < 0.30:
        if not name.endswith("_final"):
            name = name + rng.choice(["_final", "_итог", "_v2", "_согласовано", "_FINAL_v2"])
    if rng.random() < 0.28:  # пробелы вместо подчёркиваний
        name = name.replace("_", " ")
    if rng.random() < 0.10:
        name = name.upper()
    elif rng.random() < 0.08:
        name = name.lower()
    return name


def main() -> int:
    rng = random.Random(SEED)
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    rows: list[dict[str, object]] = []

    while len(rows) < COUNT:
        category = pick_category(rng)
        name, extension = base_name(category, rng)
        name = add_noise(name, rng)
        directory = rng.choice(DIRS[category])
        path = f"{directory}\\{name}{extension}"
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "id": f"synth-{len(rows) + 1:04d}",
            "path": path,
            "name": f"{name}{extension}",
            "directory": directory,
            "category": category,
            "level": LEVELS[category],
            "source": "synthetic",
        })

    with TARGET.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    from collections import Counter
    by_category = Counter(str(row["category"]) for row in rows)
    by_level = Counter(str(row["level"]) for row in rows)
    print(f"сохранено {len(rows)} строк: {TARGET}")
    print("по категориям:", dict(by_category))
    print("по классам:", dict(by_level))
    print("примеры:")
    for row in rows[:8]:
        print("  ", row["path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

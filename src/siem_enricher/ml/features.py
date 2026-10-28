"""Признаки объекта (имя и путь файла) для ML-классификатора конфиденциальности."""

from __future__ import annotations

import re
import zlib
from typing import Any, Mapping

#: Порядок признаков фиксирован: он же сохраняется в артефакт модели при обучении.
FEATURE_NAMES: tuple[str, ...] = (
    "name_len",
    "path_len",
    "path_depth",
    "digit_ratio",
    "upper_ratio",
    "special_ratio",
    "token_count",
    "avg_token_len",
    "ext_len",
    "has_extension",
    "is_archive",
    "is_document",
    "is_database",
    "is_credential_ext",
    "is_executable",
    "is_image",
    "is_mail",
    "is_crypto_ext",
    "is_credential_name",
    "has_year",
    "has_date",
    "has_cyrillic",
    "has_person_pattern",
    "has_initials",
    "has_digits_suffix",
    "kw_personal",
    "kw_finance",
    "kw_hr",
    "kw_legal",
    "kw_medical",
    "kw_secret",
    "kw_credential",
    "kw_project",
    "kw_report",
    "kw_backup",
    "kw_public",
    "kw_temp",
    "kw_commercial_secret",
    "dir_hr",
    "dir_finance",
    "dir_legal",
    "dir_secret",
    "dir_public",
    "dir_shared",
    "dir_tech",
    "is_system_path",
    "is_network_path",
    "is_removable",
    "is_tmp",
    "is_temp_ext",
    "has_copy_marker",
    "has_version_marker",
    "ext_bucket",
)

ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso"}
DOCUMENT_EXT = {".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".rtf",
                ".odt", ".ods", ".odp", ".csv", ".txt", ".md", ".xml", ".json", ".mxl"}
DATABASE_EXT = {".mdb", ".accdb", ".sql", ".bak", ".dbf", ".sqlite", ".sqlite3", ".db", ".1cd", ".dmp"}
CREDENTIAL_EXT = {".kdbx", ".kdb", ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk",
                  ".asc", ".gpg", ".pgp", ".ovpn", ".rdp", ".env"}
EXECUTABLE_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".jar", ".sh", ".py", ".hta"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp"}
MAIL_EXT = {".pst", ".ost", ".msg", ".eml", ".mbox"}
CRYPTO_EXT = {".locked", ".enc", ".crypt", ".crypto", ".encrypted", ".zepto", ".locky", ".wncry"}
TEMP_EXT = {".tmp", ".temp", ".bak1", ".old", ".swp", ".~"}

CREDENTIAL_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".env", ".htpasswd",
                    "ntds.dit", "wp-config.php", "web.config", "shadow", "passwd",
                    "credentials", "credentials.json", "secrets", "secrets.json", "keystore"}

KEYWORD_FEATURES: dict[str, re.Pattern[str]] = {
    "kw_personal": re.compile(r"(?i)(паспорт|passport|снилс|анкета|персональн|personal|pii|пдн|"
                              r"дата_рождения|адрес_регистрации|водительск|удостоверен)"),
    "kw_finance": re.compile(r"(?i)(бухгалт|accounting|счёт|счет|invoice|накладн|платеж|платёж|"
                             r"финанс|finance|бюджет|budget|смета|касс|выписка|statement|"
                             r"баланс|balance|налог|tax)"),
    "kw_hr": re.compile(r"(?i)(кадр|hr_|\bhr\b|сотрудник|employee|персонал|отпуск|vacation|"
                        r"увольнен|приказ_о_приеме|трудовой_договор|табель|штатн|резюме|resume|cv_)"),
    "kw_legal": re.compile(r"(?i)(юрид|legal|иск\b|lawsuit|суд\b|претензи|договор|contract|"
                           r"соглашени|agreement|доверенност|устав|charter|лиценз|license)"),
    "kw_medical": re.compile(r"(?i)(медиц|medical|диагноз|diagnosis|пациент|patient|health|"
                             r"больничн|анализы|прививк)"),
    "kw_secret": re.compile(r"(?i)(\bsecret\b|секрет|confidential|конфиденц|\bдсп\b|restricted|"
                            r"for_official_use|не_для_печати|особой_важности|top_secret|"
                            r"коммерческ.{0,3}тайн|trade.{0,3}secret|ноу-хау|know-how|\bnda\b)"),
    "kw_credential": re.compile(r"(?i)(password|passwd|парол|credential|учетн|учётн|логин|"
                                r"\btoken\b|api[_-]?key|secret[_-]?key|private[_-]?key|"
                                r"\bключ|ключи|\bkeys?\b|сертификат|\.pfx|\.pem|id_rsa)"),
    "kw_project": re.compile(r"(?i)(проект|project|техзадани|техническое_задани|techspec|\bтз\b|"
                             r"исходн|source|разработк|design|архитектур|схема_данных)"),
    "kw_report": re.compile(r"(?i)(отчет|отчёт|report|презентац|presentation|аналитик|analytics|"
                            r"статистик|statistics|сводк|dashboard)"),
    "kw_backup": re.compile(r"(?i)(backup|бэкап|резервн|dump|дамп|архив|snapshot|replica)"),
    "kw_public": re.compile(r"(?i)(readme|public|публичн|пресс|press|release_notes|changelog|"
                            r"шаблон|template|образец|sample|пример|example|инструкц|manual)"),
    "kw_temp": re.compile(r"(?i)(\btmp\b|\btemp\b|черновик|draft|временн|\bкопия\b|\bcopy\b|"
                          r"\bnew\b|\bold\b|unconfirmed)"),
    "kw_commercial_secret": re.compile(r"(?i)(коммерческ.{0,3}тайн|trade.{0,3}secret|ноу-хау|"
                                       r"know-how|конкурент|competitive|tender|тендер|котировк)"),
}

DIRECTORY_FEATURES: dict[str, re.Pattern[str]] = {
    "dir_hr": re.compile(r"(?i)(\\|\/)(hr|кадры|кадров|персонал|staff|persons?|employees?)(\\|\/)"),
    "dir_finance": re.compile(r"(?i)(\\|\/)(бухгалтер\w*|финанс\w*|accounting|finance|payroll|"
                              r"зарплат\w*|salary|cash|касс\w*)(\\|\/)"),
    "dir_legal": re.compile(r"(?i)(\\|\/)(юрид\w*|legal|law|договор\w*|contracts?)(\\|\/)"),
    "dir_secret": re.compile(r"(?i)(\\|\/)(секрет\w*|secret\w*|vault|keys?|крипт\w*|crypto|"
                             r"private|приватн\w*|закрыт\w*)(\\|\/)"),
    "dir_public": re.compile(r"(?i)(\\|\/)(public|публичн\w*|общие|общий_доступ|shared_public)(\\|\/)"),
    "dir_shared": re.compile(r"(?i)(\\|\/)(share|shared|обмен|сетевой_диск|netlogon|dfs)(\\|\/)"),
    "dir_tech": re.compile(r"(?i)(\\|\/)(проект\w*|projects?|dev|src|build|deploy|backup|"
                           r"резервн\w*|архив\w*|tmp|temp)(\\|\/)"),
}

SYSTEM_PATH_RE = re.compile(r"(?i)^(c:\\windows\\|c:\\program files|/usr/|/etc/|/var/lib/|/proc/|/sys/)")
NETWORK_PATH_RE = re.compile(r"^\\\\[^\\]+\\")
REMOVABLE_PATH_RE = re.compile(r"(?i)(\\\\removable|\\usb|/media/|/mnt/|[e-z]:\\)")
TMP_PATH_RE = re.compile(r"(?i)(\\temp\\|\\tmp\\|/tmp/|\\appdata\\local\\temp)")
YEAR_RE = re.compile(r"(19|20)\d{2}")
DATE_RE = re.compile(r"\b\d{2}[.\-_/]\d{2}[.\-_/]\d{2,4}\b")
CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
PERSON_RE = re.compile(r"[А-ЯЁ][а-яё]{2,}(?:[_\-\s][А-ЯЁ][а-яё]{2,})")
INITIALS_RE = re.compile(r"[А-ЯЁ][а-яё]{2,}[_\-\s]?[А-ЯЁ]\.?[А-ЯЁ]?\.?")
DIGITS_SUFFIX_RE = re.compile(r"(\d{2,}|\s\(\d+\)|_v?\d+(\.\d+)*)$")
COPY_MARKER_RE = re.compile(r"(?i)(\bкопия\b|\bcopy\b|\s-\sкопия|\(1\)|\(2\)|_copy|_копия)")
VERSION_MARKER_RE = re.compile(r"(?i)(_v\d+|версия\s*\d+|version\s*\d+|\bfinal\b|\bитог\w*)")


def _extension(name: str) -> str:
    lower = name.lower()
    for composite in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(composite):
            return composite
    if "." in name[1:]:
        return "." + lower.rsplit(".", 1)[1]
    return ""


def extract_features(path: str) -> dict[str, float]:
    """Построить вектор признаков по пути (или имени) файла."""
    raw = (path or "").strip().strip('"\'')
    normalized = raw.replace("/", "\\")
    name = normalized.rsplit("\\", 1)[-1] if normalized else ""
    ext = _extension(name)
    stem = name[: -len(ext)] if ext else name

    features: dict[str, float] = {}
    features["name_len"] = float(len(name))
    features["path_len"] = float(len(normalized))
    features["path_depth"] = float(max(0, normalized.count("\\")))
    features["digit_ratio"] = _ratio(name, str.isdigit)
    features["upper_ratio"] = _ratio(name, str.isupper)
    features["special_ratio"] = _ratio(name, lambda ch: not ch.isalnum() and ch != " ")
    tokens = [t for t in re.split(r"[\s._\-()\[\]]+", stem) if t]
    features["token_count"] = float(len(tokens))
    features["avg_token_len"] = float(sum(len(t) for t in tokens)) / len(tokens) if tokens else 0.0
    features["ext_len"] = float(len(ext))
    features["has_extension"] = 1.0 if ext else 0.0
    features["is_archive"] = 1.0 if ext in ARCHIVE_EXT else 0.0
    features["is_document"] = 1.0 if ext in DOCUMENT_EXT else 0.0
    features["is_database"] = 1.0 if ext in DATABASE_EXT else 0.0
    features["is_credential_ext"] = 1.0 if ext in CREDENTIAL_EXT else 0.0
    features["is_executable"] = 1.0 if ext in EXECUTABLE_EXT else 0.0
    features["is_image"] = 1.0 if ext in IMAGE_EXT else 0.0
    features["is_mail"] = 1.0 if ext in MAIL_EXT else 0.0
    features["is_crypto_ext"] = 1.0 if ext in CRYPTO_EXT else 0.0
    features["is_credential_name"] = 1.0 if name.lower() in CREDENTIAL_NAMES else 0.0
    features["has_year"] = 1.0 if YEAR_RE.search(stem) else 0.0
    features["has_date"] = 1.0 if DATE_RE.search(stem) else 0.0
    features["has_cyrillic"] = 1.0 if CYRILLIC_RE.search(stem) else 0.0
    features["has_person_pattern"] = 1.0 if PERSON_RE.search(stem) else 0.0
    features["has_initials"] = 1.0 if INITIALS_RE.search(stem) else 0.0
    features["has_digits_suffix"] = 1.0 if DIGITS_SUFFIX_RE.search(stem) else 0.0

    for feature_name, pattern in KEYWORD_FEATURES.items():
        features[feature_name] = 1.0 if pattern.search(name) else 0.0

    for feature_name, pattern in DIRECTORY_FEATURES.items():
        features[feature_name] = 1.0 if pattern.search(normalized) else 0.0

    features["is_system_path"] = 1.0 if SYSTEM_PATH_RE.search(normalized) else 0.0
    features["is_network_path"] = 1.0 if NETWORK_PATH_RE.search(normalized) else 0.0
    features["is_removable"] = 1.0 if REMOVABLE_PATH_RE.search(normalized) else 0.0
    features["is_tmp"] = 1.0 if TMP_PATH_RE.search(normalized) else 0.0
    features["is_temp_ext"] = 1.0 if ext in TEMP_EXT or name.endswith("~") else 0.0
    features["has_copy_marker"] = 1.0 if COPY_MARKER_RE.search(stem) else 0.0
    features["has_version_marker"] = 1.0 if VERSION_MARKER_RE.search(stem) else 0.0
    # Стабильный «бакет» расширения — грубая категориальная кодировка без One-Hot
    features["ext_bucket"] = (zlib.crc32(ext.encode("utf-8")) % 100) / 100.0 if ext else 0.0

    return features


def _ratio(text: str, predicate: Any) -> float:
    if not text:
        return 0.0
    matches = sum(1 for ch in text if predicate(ch))
    return matches / len(text)


def features_to_vector(features: Mapping[str, float]) -> list[float]:
    """Преобразовать словарь признаков в вектор фиксированного порядка."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def feature_importance_hint(features: Mapping[str, float], top: int = 5) -> list[str]:
    """Список «объяснений»: признаки с наибольшим вкладом (для журнала и отчёта)."""
    human = {
        "kw_credential": "имя содержит признаки учётных данных",
        "kw_secret": "имя содержит признаки секретных данных",
        "kw_personal": "имя содержит признаки персональных данных",
        "kw_finance": "имя содержит признаки финансовых данных",
        "kw_hr": "имя содержит признаки кадровых данных",
        "kw_legal": "имя содержит признаки юридических документов",
        "kw_medical": "имя содержит признаки медицинских данных",
        "kw_commercial_secret": "имя содержит признаки коммерческой тайны",
        "kw_backup": "имя содержит признаки резервной копии",
        "kw_public": "имя содержит признаки открытых данных",
        "kw_temp": "имя содержит признаки черновика/копии",
        "is_credential_ext": "расширение относится к криптоматериалам",
        "is_credential_name": "имя файла типовое для хранилища секретов",
        "is_database": "расширение относится к базам данных",
        "is_mail": "расширение относится к почтовым архивам",
        "is_archive": "файл является архивом",
        "dir_hr": "каталог относится к кадровому делопроизводству",
        "dir_finance": "каталог относится к бухгалтерии/финансам",
        "dir_legal": "каталог относится к юридическому департаменту",
        "dir_secret": "каталог предназначен для секретных данных",
        "dir_public": "каталог общего доступа",
        "is_removable": "путь указывает на съёмный носитель",
        "is_network_path": "путь указывает на сетевой ресурс",
        "has_person_pattern": "имя похоже на ФИО",
        "has_initials": "имя содержит инициалы",
    }
    scored = [
        (value, name) for name, value in features.items()
        if value and name in human
    ]
    scored.sort(key=lambda item: item[0], reverse=True)
    return [human[name] for _, name in scored[:top]]

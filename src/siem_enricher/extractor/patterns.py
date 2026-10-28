"""Регулярные выражения, словари расширений и вспомогательные функции разбора путей."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Iterator

WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]{0,180}")
UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9._-]{1,64}\\[^\r\n\t\"'<>|]{1,180}")
UNIX_PATH_RE = re.compile(r"/(?:[^/\0\s\"'<>|]{1,64}/){1,12}[^/\0\s\"'<>|]{1,120}")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]{4,300}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|su|io|biz|info|xyz|top|site|online|cloud|dev|local|internal|onion)\b",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")

#: Хвостовой «мусор» в текстовых сообщениях SIEM: ``file.xlsx (read)``, ``doc.pdf [copy]``.
#: Применяется только при сканировании текстовых полей, чтобы не портить реальные имена файлов.
ACTION_SUFFIX_RE = re.compile(
    r"\s*[\(\[]\s*(?:read|write|copy|move|rename|delete|execute|archive|encrypt|decrypt"
    r"|upload|send|open|edit|access|created|modified|removed)\s*[\)\]]\s*$",
    re.IGNORECASE,
)

#: Файлы, наличие которых само по себе указывает на высокий класс конфиденциальности
CREDENTIAL_EXTENSIONS = frozenset(
    {".kdbx", ".kdb", ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk",
     ".asc", ".gpg", ".pgp", ".ovpn", ".rdp", ".keychain", ".jceks"}
)
CREDENTIAL_FILE_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "shadow", "passwd", "credentials",
     "secrets", ".env", ".htpasswd", "wp-config.php", "web.config", "ntds.dit",
     "sam", "security", "unattend.xml", "sysprep.xml", "terraform.tfstate"}
)
ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso", ".lz", ".lzma", ".zst"})
DOCUMENT_EXTENSIONS = frozenset(
    {".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".rtf", ".odt",
     ".ods", ".odp", ".csv", ".txt", ".md", ".xml", ".json", ".1c", ".mxl"}
)
DATABASE_EXTENSIONS = frozenset({".mdb", ".accdb", ".sql", ".bak", ".dbf", ".sqlite", ".sqlite3", ".db", ".1cd", ".dmp"})
CRYPTO_EXTENSIONS = frozenset({".locked", ".enc", ".crypt", ".crypto", ".encrypted", ".zepto", ".locky", ".wncry", ".wcry", ".ryk", ".cerber"})
EXECUTABLE_EXTENSIONS = frozenset({".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msi", ".jar", ".sh", ".py", ".hta"})
IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp"})
MAIL_EXTENSIONS = frozenset({".pst", ".ost", ".msg", ".eml", ".mbox"})

#: Ключи, значение которых с высокой вероятностью является целевым файлом
STRONG_FILE_KEYS = frozenset(
    {"targetfilename", "newfilename", "objectname", "filename", "filepath", "fullpath",
     "sourcefilename", "oldfilename", "targetfile", "sourcefile", "file_name",
     "targetpath", "destinationfilename", "downloadpath", "attachmentname"}
)
#: Ключи, значение которых является файлом только в определённом контексте
WEAK_FILE_KEYS = frozenset({"path", "name", "file", "destination", "source", "location"})
#: Родительские сегменты, при которых ``WEAK_FILE_KEYS`` считаются путём к файлу
FILE_CONTEXT_SEGMENTS = frozenset(
    {"file", "files", "targetfile", "sourcefile", "destinationfile", "object", "attachment", "syscheck"}
)

#: Ключи, в значениях которых имеет смысл искать пути (командные строки, сообщения и т.п.)
EMBEDDED_SCAN_KEYS = frozenset(
    {"commandline", "cmdline", "processcommandline", "command", "message", "full_log",
     "fulllog", "url", "requesturl", "destinationurl", "query", "args", "arguments",
     "scriptblocktext", "targetobject", "details"}
)

SYSTEM_PATH_PREFIXES_DEFAULT: tuple[str, ...] = (
    "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
    "/proc/", "/sys/", "/dev/", "/usr/lib/", "/usr/share/",
)

PRIVILEGED_USER_NAMES = frozenset(
    {"administrator", "admin", "root", "system", "local system", "nt authority\\system",
     "sa", "sysadmin", "domain admin", "администратор"}
)

REMOVABLE_PATH_RE = re.compile(r"(?i)(\\\\removable|\\usb|/media/|/mnt/|/run/media/|[e-z]:\\)")
NETWORK_PATH_RE = re.compile(r"^\\\\[^\\]+\\")


def extension_of(path: str) -> str:
    """Расширение файла в нижнем регистре (с учётом составных вроде ``.tar.gz``)."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    lower = name.lower()
    for composite in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"):
        if lower.endswith(composite):
            return composite
    if "." in name[1:]:
        return "." + name.rsplit(".", 1)[1].lower()
    return ""


def normalize_path(path: str) -> str:
    """Нормализовать путь: убрать кавычки, лишние пробелы, привести разделители."""
    value = path.strip().strip('"\'').rstrip(".,;:")
    if not value:
        return ""
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        value = value.replace("/", "\\")
        if re.match(r"^[A-Za-z]:", value):
            value = value[0].upper() + value[1:]
    return value


def looks_like_path(value: str) -> bool:
    """Похоже ли значение на путь к файлу."""
    if not value or len(value) < 4 or len(value) > 512:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if value.startswith("\\\\"):
        return True
    if value.startswith("/") and value.count("/") >= 1 and " " not in value:
        return True
    return False


#: Хвост вида ``" E"`` — начало следующего пути (``file.xlsx E:\other.xlsx``)
DANGLING_DRIVE_RE = re.compile(r"\s+[A-Za-z]$")


def find_paths(text: str, limit: int = 16) -> list[str]:
    """Найти все похожие на пути подстроки в произвольном тексте."""
    found: list[str] = []
    if not text or len(text) > 8000:
        return found
    for pattern in (WINDOWS_PATH_RE, UNC_PATH_RE, UNIX_PATH_RE):
        position = 0
        while position < len(text):
            match = pattern.search(text, position)
            if match is None:
                break
            raw = match.group(0)
            trimmed = DANGLING_DRIVE_RE.sub("", raw)
            if trimmed != raw and text[match.end():match.end() + 1] == ":":
                # совпадение захватило букву диска следующего пути — возвращаем её в поток
                advance = match.start() + len(trimmed)
            else:
                trimmed = raw
                advance = match.end()
            candidate = normalize_path(ACTION_SUFFIX_RE.sub("", trimmed))
            if looks_like_path(candidate) and candidate not in found:
                found.append(candidate)
                if len(found) >= limit:
                    return found
            position = max(advance, match.start() + 1)
    return found


def is_private_ip(value: str) -> bool:
    """Является ли адрес приватным/локальным."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def is_external_ip(value: str) -> bool:
    """Является ли адрес внешним (маршрутизируемым)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved)


def is_removable_path(path: str) -> bool:
    return bool(REMOVABLE_PATH_RE.search(path))


def is_network_path(path: str) -> bool:
    return bool(NETWORK_PATH_RE.match(path))


def is_system_path(path: str, prefixes: Iterable[str] = SYSTEM_PATH_PREFIXES_DEFAULT) -> bool:
    lowered = path.lower().replace("/", "\\") if ":" in path[:3] else path.lower()
    for prefix in prefixes:
        normalized_prefix = prefix.lower().replace("/", "\\") if ":" in prefix[:3] else prefix.lower()
        if lowered.startswith(normalized_prefix):
            return True
    return False


def is_privileged_user(name: str | None) -> bool:
    """Отнести пользователя к привилегированным по имени."""
    if not name:
        return False
    lowered = name.strip().lower()
    if lowered in PRIVILEGED_USER_NAMES:
        return True
    return any(marker in lowered for marker in ("admin", "root", "systеm", "system", "администрат"))


def find_ip(value: str) -> str | None:
    match = IPV4_RE.search(value or "")
    return match.group(0) if match else None


def find_url(value: str) -> str | None:
    match = URL_RE.search(value or "")
    return match.group(0) if match else None


def find_domain(value: str) -> str | None:
    match = DOMAIN_RE.search(value or "")
    return match.group(0) if match else None


def find_hashes(value: str) -> dict[str, str]:
    """Извлечь хэши из строки (в том числе из составных полей Wazuh вида ``SHA256=...``)."""
    result: dict[str, str] = {}
    if not value:
        return result
    sha = SHA256_RE.search(value)
    if sha:
        result["sha256"] = sha.group(0).lower()
    md5 = MD5_RE.search(value)
    if md5 and md5.group(0).lower() != result.get("sha256"):
        result["md5"] = md5.group(0).lower()
    return result


def iter_strings(obj: object, max_items: int = 5000) -> Iterator[str]:
    """Обойти произвольную структуру и вернуть все строковые значения."""
    stack: list[object] = [obj]
    seen = 0
    while stack and seen < max_items:
        current = stack.pop()
        seen += 1
        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, (list, tuple, set)):
            stack.extend(current)

PLURAL_FILE_KEYS = frozenset({"targetfilenames", "filenames", "filelist", "paths"})
STRONG_FILE_KEYS = STRONG_FILE_KEYS | PLURAL_FILE_KEYS
FILE_LIST_SPLIT_RE = re.compile(r"[;|,]\s*")


def split_file_list(value: str) -> list[str]:
    """Разбить значение поля со списком файлов на отдельные пути."""
    return [part.strip() for part in FILE_LIST_SPLIT_RE.split(value or "") if part.strip()]

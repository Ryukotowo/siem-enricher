"""Эвристический классификатор конфиденциальности."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Iterable, Sequence

from siem_enricher.ml.base import SensitivityClassifier
from siem_enricher.ml.features import extract_features, feature_importance_hint
from siem_enricher.models.enums import SensitivityLevel
from siem_enricher.models.enrichment import SensitivityAssessment


@dataclass(frozen=True, slots=True)
class KeywordRule:
    """Правило сопоставления по регулярному выражению."""

    name: str
    level: SensitivityLevel
    weight: float
    pattern: re.Pattern[str]
    note: str = ""
    #: Признак размещения/пометки (организационное решение), а не признак содержания
    policy: bool = False


def _rule(
    name: str,
    level: SensitivityLevel,
    weight: float,
    regex: str,
    note: str = "",
    policy: bool = False,
) -> KeywordRule:
    return KeywordRule(name, level, weight, re.compile(regex), note, policy)


#: Правила по имени файла (без учёта каталога)
FILENAME_RULES: tuple[KeywordRule, ...] = (
    _rule("passwords", SensitivityLevel.SECRET, 1.8,
          r"(?i)(password|passwd|парол|credential|учетн|учётн|\blogin|token|api[_-]?key|"
          r"secret[_-]?key|private[_-]?key|\bключ|ключи|\bkeys?\b)",
          "имя указывает на учётные данные или ключи",
          policy=True),
    _rule("secrets_dir_marker", SensitivityLevel.SECRET, 1.5,
          r"(?i)(\bsecret\b|секрет|особой_важности|top[_-]?secret|не_для_печати|for[_-]?official[_-]?use)",
          "имя содержит пометку ограниченного доступа",
          policy=True),
    _rule("confidential_marker", SensitivityLevel.CONFIDENTIAL, 1.3,
          r"(?i)(confidential|конфиденц|\bдсп\b|restricted|internal[_-]?only)",
          "имя содержит гриф конфиденциальности",
          policy=True),
    _rule("personal_data", SensitivityLevel.CONFIDENTIAL, 1.4,
          r"(?i)(паспорт|passport|снилс|анкета|персональн|personal|\bpii\b|\bпдн\b|"
          r"водительск|удостоверен|дата_рождения)",
          "имя указывает на персональные данные"),
    _rule("medical", SensitivityLevel.CONFIDENTIAL, 1.5,
          r"(?i)(медиц|medical|диагноз|diagnosis|пациент|patient|больничн|анализы|прививк)",
          "имя указывает на медицинские данные (спецкатегория ПДн)"),
    _rule("payroll", SensitivityLevel.CONFIDENTIAL, 1.6,
          r"(?i)(зарплат|ведомост|payroll|salary|оклад|табель|штатн|преми|bonus)",
          "имя указывает на расчёт заработной платы"),
    _rule("hr", SensitivityLevel.CONFIDENTIAL, 1.2,
          r"(?i)(кадр|\bhr\b|hr_|сотрудник|employee|персонал|отпуск|vacation|увольнен|"
          r"трудовой_договор|резюме|resume)",
          "имя указывает на кадровые документы"),
    _rule("finance", SensitivityLevel.CONFIDENTIAL, 1.3,
          r"(?i)(бухгалт|accounting|invoice|накладн|платеж|платёж|финанс|finance|бюджет|"
          r"budget|смета|касс|выписка|statement|баланс|налог)",
          "имя указывает на финансовые документы"),
    _rule("legal", SensitivityLevel.CONFIDENTIAL, 1.1,
          r"(?i)(юрид|legal|иск\b|lawsuit|претензи|договор|contract|соглашени|agreement|"
          r"доверенност|устав|charter)",
          "имя указывает на юридические документы"),
    _rule("clients", SensitivityLevel.CONFIDENTIAL, 1.1,
          r"(?i)(клиент|client|customer|\bcrm\b|сделк|deal|абонент|договор_поставки)",
          "имя указывает на клиентскую базу"),
    _rule("commercial_secret", SensitivityLevel.CONFIDENTIAL, 1.4,
          r"(?i)(коммерческ.{0,3}тайн|trade.{0,3}secret|ноу-хау|know-how|\bnda\b|тендер|котировк)",
          "имя указывает на коммерческую тайну"),
    _rule("infrastructure", SensitivityLevel.INTERNAL, 0.8,
          r"(?i)(схема|network|network_map|конфиг|config|настройк|инфраструктур|"
          r"регламент|инструкц|policy|политика)",
          "имя указывает на внутренние регламенты и схемы"),
    _rule("project", SensitivityLevel.INTERNAL, 0.7,
          r"(?i)(проект|project|техзадани|\bтз\b|исходн|source|разработк|design|архитектур)",
          "имя указывает на проектные материалы"),
    _rule("report", SensitivityLevel.INTERNAL, 0.5,
          r"(?i)(отчет|отчёт|report|презентац|presentation|аналитик|сводк|статистик)",
          "имя указывает на отчётные материалы"),
    _rule("backup", SensitivityLevel.INTERNAL, 0.5,
          r"(?i)(backup|бэкап|резервн|dump|дамп|snapshot|архив)",
          "имя указывает на резервную копию"),
    _rule("public", SensitivityLevel.PUBLIC, 1.0,
          r"(?i)^(readme|license|changelog|public_|пресс|press_|шаблон|template|образец|"
          r"sample|пример|example)",
          "имя указывает на открытые данные",
          policy=True),
)

#: Правила по каталогу размещения
DIRECTORY_RULES: tuple[KeywordRule, ...] = (
    _rule("dir_secret", SensitivityLevel.SECRET, 1.6,
          r"(?i)(\\|/)(секрет\w*|secret\w*|vault|keys?|крипт\w*|private|приватн\w*|закрыт\w*)(\\|/)",
          "каталог предназначен для секретных данных"),
    _rule("dir_payroll", SensitivityLevel.CONFIDENTIAL, 1.6,
          r"(?i)(\\|/)(зарплат\w*|payroll|salary)(\\|/)",
          "каталог расчёта заработной платы"),
    _rule("dir_hr", SensitivityLevel.CONFIDENTIAL, 1.4,
          r"(?i)(\\|/)(hr|кадры|кадров\w*|персонал|staff|employees?)(\\|/)",
          "кадровый каталог"),
    _rule("dir_finance", SensitivityLevel.CONFIDENTIAL, 1.4,
          r"(?i)(\\|/)(бухгалтер\w*|финанс\w*|accounting|finance|cash|касс\w*)(\\|/)",
          "финансовый каталог"),
    _rule("dir_personal", SensitivityLevel.CONFIDENTIAL, 1.4,
          r"(?i)(\\|/)(персональн\w*|personal|\bpii\b|\bпдн\b|клиент\w*|clients?)(\\|/)",
          "каталог персональных данных"),
    _rule("dir_legal", SensitivityLevel.CONFIDENTIAL, 1.2,
          r"(?i)(\\|/)(юрид\w*|legal|law|договор\w*|contracts?)(\\|/)",
          "юридический каталог"),
    _rule("dir_project", SensitivityLevel.INTERNAL, 0.8,
          r"(?i)(\\|/)(проект\w*|projects?|dev|src|разработк\w*)(\\|/)",
          "каталог проектных материалов"),
    _rule("dir_archive", SensitivityLevel.INTERNAL, 0.6,
          r"(?i)(\\|/)(backup|резервн\w*|архив\w*|archive)(\\|/)",
          "каталог архивов и резервных копий"),
    _rule("dir_public", SensitivityLevel.PUBLIC, 0.8,
          r"(?i)(\\|/)(public|публичн\w*|общие|общий_доступ|shared_public)(\\|/)",
          "каталог общего доступа"),
)

# Каталог размещения определяет организационное решение о классе объекта, а не гипотезу
# о содержании, поэтому все правила по каталогам помечаются приоритетными (см. ml.hybrid).
DIRECTORY_RULES = tuple(replace(rule, policy=True) for rule in DIRECTORY_RULES)

#: Правила по расширению файла
EXTENSION_RULES: dict[str, tuple[SensitivityLevel, float, str]] = {
    ".kdbx": (SensitivityLevel.SECRET, 2.0, "хранилище паролей KeePass"),
    ".kdb": (SensitivityLevel.SECRET, 1.8, "хранилище паролей"),
    ".pem": (SensitivityLevel.SECRET, 1.8, "сертификат/ключ в формате PEM"),
    ".key": (SensitivityLevel.SECRET, 1.8, "файл закрытого ключа"),
    ".pfx": (SensitivityLevel.SECRET, 1.8, "контейнер с закрытым ключом"),
    ".p12": (SensitivityLevel.SECRET, 1.8, "контейнер с закрытым ключом"),
    ".jks": (SensitivityLevel.SECRET, 1.6, "хранилище ключей Java"),
    ".ppk": (SensitivityLevel.SECRET, 1.6, "закрытый ключ PuTTY"),
    ".keystore": (SensitivityLevel.SECRET, 1.6, "хранилище ключей"),
    ".gpg": (SensitivityLevel.SECRET, 1.4, "зашифрованный архив"),
    ".pgp": (SensitivityLevel.SECRET, 1.4, "зашифрованный архив"),
    ".asc": (SensitivityLevel.SECRET, 1.2, "криптографический файл"),
    ".env": (SensitivityLevel.SECRET, 1.6, "файл переменных окружения с секретами"),
    ".ovpn": (SensitivityLevel.CONFIDENTIAL, 1.2, "профиль VPN"),
    ".rdp": (SensitivityLevel.CONFIDENTIAL, 1.0, "профиль удалённого подключения"),
    ".sql": (SensitivityLevel.CONFIDENTIAL, 1.2, "дамп базы данных"),
    ".bak": (SensitivityLevel.CONFIDENTIAL, 1.0, "резервная копия"),
    ".dbf": (SensitivityLevel.CONFIDENTIAL, 1.0, "файл базы данных"),
    ".mdb": (SensitivityLevel.CONFIDENTIAL, 1.0, "файл базы данных Access"),
    ".accdb": (SensitivityLevel.CONFIDENTIAL, 1.0, "файл базы данных Access"),
    ".1cd": (SensitivityLevel.CONFIDENTIAL, 1.2, "файл базы 1С"),
    ".sqlite": (SensitivityLevel.CONFIDENTIAL, 1.0, "файл базы данных"),
    ".pst": (SensitivityLevel.CONFIDENTIAL, 1.2, "почтовый архив Outlook"),
    ".ost": (SensitivityLevel.CONFIDENTIAL, 1.2, "почтовый архив Outlook"),
    ".msg": (SensitivityLevel.CONFIDENTIAL, 0.9, "сообщение электронной почты"),
    ".eml": (SensitivityLevel.CONFIDENTIAL, 0.9, "файл электронного письма"),
    ".doc": (SensitivityLevel.INTERNAL, 0.5, "документ"),
    ".docx": (SensitivityLevel.INTERNAL, 0.5, "документ"),
    ".xls": (SensitivityLevel.INTERNAL, 0.6, "электронная таблица"),
    ".xlsx": (SensitivityLevel.INTERNAL, 0.6, "электронная таблица"),
    ".xlsm": (SensitivityLevel.INTERNAL, 0.6, "электронная таблица с макросами"),
    ".pdf": (SensitivityLevel.INTERNAL, 0.5, "PDF-документ"),
    ".pptx": (SensitivityLevel.INTERNAL, 0.5, "презентация"),
    ".csv": (SensitivityLevel.INTERNAL, 0.4, "табличные данные"),
    ".txt": (SensitivityLevel.INTERNAL, 0.3, "текстовый файл"),
    ".log": (SensitivityLevel.INTERNAL, 0.3, "журнал"),
    ".json": (SensitivityLevel.INTERNAL, 0.3, "структурированные данные"),
    ".exe": (SensitivityLevel.PUBLIC, 0.4, "исполняемый файл"),
    ".dll": (SensitivityLevel.PUBLIC, 0.4, "библиотека"),
    ".png": (SensitivityLevel.INTERNAL, 0.2, "изображение"),
    ".jpg": (SensitivityLevel.INTERNAL, 0.2, "изображение"),
}

#: Точные имена файлов, однозначно относящиеся к секретам
CREDENTIAL_FILENAMES: frozenset[str] = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".env", ".htpasswd", "ntds.dit",
     "wp-config.php", "web.config", "shadow", "passwd", "credentials", "credentials.json",
     "secrets", "secrets.json", "keystore", "unattend.xml"}
)


class HeuristicSensitivityClassifier(SensitivityClassifier):
    """Классификатор на основе взвешенных правил по имени, каталогу и расширению."""

    method = "heuristic"

    def __init__(
        self,
        default_level: SensitivityLevel = SensitivityLevel.INTERNAL,
        model_version: str = "heuristic-0.1.0",
        confidence_floor: float = 0.35,
        filename_rules: Sequence[KeywordRule] = FILENAME_RULES,
        directory_rules: Sequence[KeywordRule] = DIRECTORY_RULES,
        extension_rules: dict[str, tuple[SensitivityLevel, float, str]] | None = None,
    ) -> None:
        self.default_level = default_level
        self.model_version = model_version
        self.confidence_floor = confidence_floor
        self.filename_rules = tuple(filename_rules)
        self.directory_rules = tuple(directory_rules)
        self.extension_rules = dict(extension_rules or EXTENSION_RULES)

    def predict(self, path: str) -> SensitivityAssessment:
        return self.predict_many([path])[0]

    def predict_many(self, paths: Iterable[str]) -> list[SensitivityAssessment]:
        return [self._predict_one(path) for path in paths]

    def _predict_one(self, path: str) -> SensitivityAssessment:
        features = extract_features(path)
        name = (path or "").replace("/", "\\").rsplit("\\", 1)[-1]
        extension = _extension_of(name)

        scores: dict[SensitivityLevel, float] = {level: 0.0 for level in SensitivityLevel.labels()}
        policy_scores: dict[SensitivityLevel, float] = {level: 0.0 for level in SensitivityLevel.labels()}
        evidence: list[str] = []

        if name.lower() in CREDENTIAL_FILENAMES:
            scores[SensitivityLevel.SECRET] += 2.0
            policy_scores[SensitivityLevel.SECRET] += 2.0
            evidence.append(f"имя {name!r} типовое для хранилища секретов")

        ext_rule = self.extension_rules.get(extension)
        if ext_rule:
            level, weight, note = ext_rule
            scores[level] += weight
            if level is SensitivityLevel.SECRET:
                # расширения криптоматериалов (.kdbx, .pem, .key) — признак размещения секретов
                policy_scores[level] += weight
            evidence.append(note)

        for rule in self.filename_rules:
            if rule.pattern.search(name):
                scores[rule.level] += rule.weight
                if rule.policy:
                    policy_scores[rule.level] += rule.weight
                evidence.append(rule.note or rule.name)

        for rule in self.directory_rules:
            if rule.pattern.search(path or ""):
                scores[rule.level] += rule.weight
                if rule.policy:
                    policy_scores[rule.level] += rule.weight
                evidence.append(rule.note or rule.name)

        score_map = {
            **{level.value: round(score, 4) for level, score in scores.items()},
            **{
                f"policy:{level.value}": round(score, 4)
                for level, score in policy_scores.items()
                if score > 0
            },
        }

        best_level, best_score = self._argmax(scores)
        if best_score <= 0.0:
            return SensitivityAssessment(
                target=path,
                level=self.default_level,
                confidence=0.30,
                method="default",
                model_version=self.model_version,
                reason="правила не сработали, применён класс по умолчанию",
                evidence=feature_importance_hint(features),
                scores=score_map,
            )

        confidence = min(0.95, 0.45 + 0.12 * best_score)
        return SensitivityAssessment(
            target=path,
            level=best_level,
            confidence=round(confidence, 4),
            method=self.method,
            model_version=self.model_version,
            reason="; ".join(dict.fromkeys(evidence[:4])),
            evidence=list(dict.fromkeys(evidence))[:8],
            scores=score_map,
        )

    @staticmethod
    def _argmax(scores: dict[SensitivityLevel, float]) -> tuple[SensitivityLevel, float]:
        best_level = SensitivityLevel.INTERNAL
        best_score = 0.0
        for level in SensitivityLevel.labels():  # порядок возрастания ранга: ничья -> более высокий класс
            score = scores.get(level, 0.0)
            if score >= best_score and score > 0:
                best_level, best_score = level, score
        return best_level, best_score


def _extension_of(name: str) -> str:
    lowered = name.lower()
    for composite in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lowered.endswith(composite):
            return composite
    if "." in name[1:]:
        return "." + lowered.rsplit(".", 1)[1]
    return ""


def heuristic_label(path: str, classifier: HeuristicSensitivityClassifier | None = None) -> str:
    """Вспомогательная функция разметки — используется генератором датасета."""
    return (classifier or HeuristicSensitivityClassifier()).predict(path).level.value

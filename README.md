# siem-enricher — сервис обогащения событий SIEM

[![ci](https://github.com/Ryukotowo/siem-enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/Ryukotowo/siem-enricher/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![tests](https://img.shields.io/badge/tests-152-brightgreen)

Программное средство для ВКР: сервис, который встраивается в конвейер обработки событий SIEM
и дополняет каждое событие сведениями, которых в нём нет:

| Поле | Смысл | Кто считает |
|---|---|---|
| `data_sensitivity` | класс конфиденциальности объекта (`public` → `secret`) | ML-модель (mBERT по имени файла) + правила по каталогу и пометкам |
| `provenance_chain` | цепочка происхождения: чтение → копирование → архивирование → отправка | модуль provenance |
| `risk_score`, `risk_severity` | оценка риска 0…1 и уровень критичности | риск-скоринг |
| `policy_actions` | сработавшие правила и выполненные действия (маскирование, алерт, блокировка) | модуль политик |

Обогащённые события возвращаются в SIEM (Kafka) для корреляции и реагирования.

## Качество кода

- `ruff check src tests` — без замечаний; правила в `pyproject.toml`
- `python -m unittest discover -s tests -t .` — 152 теста
- CI на GitHub Actions: линтер, тесты на Python 3.11 и 3.12, проверка конфигурации
  при каждом push и pull request

```bash
pip install -e .
ruff check src tests
python -m unittest discover -s tests -t .
```

## Правила организации без правки кода

Файлы правил лежат в `config/` и накладываются на встроенные при старте:

| Файл | Что настраивает |
|---|---|
| `config/rules.json` | каталоги, шаблоны имён, расширения |
| `config/sensitivity_labels.json` | карта категорий модели в классы |
| `config/policies.json` | правила реакции (POL-001…POL-013) |

Правило из `rules.json` с тем же `id`, что и встроенное, заменяет его; новый `id`
добавляется; `enabled: false` отключает. Пример:

```json
{
  "directories": [
    {"id": "dir_contracts_org", "enabled": true, "level": "confidential",
     "weight": 1.3, "pattern": "(?i)(\\\\|/)(договор\\w*|контракт\\w*)(\\\\|/)",
     "note": "каталог договоров"}
  ]
}
```

Применить без перезапуска: кнопка **«перечитать правила»** в настройках панели или

```bash
curl -X POST http://localhost:8081/ui/rules/reload -H "X-Analyst: admin"
```

Путь к файлу задаётся в конфигурации: `ml.rules_file` (по умолчанию `config/rules.json`).

## Несколько организаций на одном сервисе

Организация задаётся в конфигурации:

```json
{"service": {"tenant": "org1"}}
```

Имя нормализуется (кириллица сохраняется, пробелы заменяются на дефис).
Значение `default` — общий режим, совместимый с прежним поведением.

Что разделяется:

| Данные | Расположение при `tenant: org1` |
|---|---|
| метки аналитика | `var/labels/org1/analyst_labels.jsonl` |
| настройки панели | `var/runtime-settings-org1.json` |
| дообученная модель | `ml/artifacts/org1/sensitivity_feedback` |
| отчёт об обучении | `var/labels/org1/training_report.json` |

Правила и политики общие (`config/rules.json`, `config/policies.json`), но каждая
организация поднимает свой экземпляр сервиса со своей конфигурацией. При значении
`ml.artifact_path: "auto"` модель берётся из каталога своей организации, а если там
пусто — из общего.

Обучение для организации:

```bash
python tools/train_from_labels.py --input var/labels/org1/dataset.jsonl --tenant org1
```

## Обучение в контейнере (профиль trainer)

Сервис-обогатитель намеренно лёгкий: torch в него не входит. Обучение вынесено
в отдельный образ:

```bash
# только проверить датасет
docker compose --profile trainer run --rm trainer --dry-run

# обучить для организации org1 (метки берутся из var/labels/org1/dataset.jsonl)
docker compose --profile trainer run --rm trainer --tenant org1

# ограничить проверку регрессии 60 путями (экономит память)
docker compose --profile trainer run --rm trainer --regression-limit 60
```

Образ собирается один раз: `docker compose --profile trainer build trainer`.
Каталоги `ml/` и `var/` монтируются с хоста, поэтому веса и метки остаются вне
образа. Модель загружается однократно: на ней снимаются метрики «до», затем
голова заменяется на 4 класса и выполняется дообучение; SGD с моментом вместо
AdamW снижает потребление памяти, что важно для машин с 8 ГБ.

### Пороги приёмки и проверка артефактов

Параметры обучения задаются конфигурацией, флаги CLI их перекрывают:

```json
{"ml": {"training_min_gain": -0.02,
        "training_regression_limit": 120,
        "training_min_rows": 20,
        "training_epochs": 3,
        "training_learning_rate": 2e-05}}
```

При регистрации версии считается манифест с контрольными суммами файлов
(`manifest.json` внутри каталога версии). Проверка:

```bash
python tools/verify_artifacts.py            # активная версия
python tools/verify_artifacts.py --all      # все версии
python tools/verify_artifacts.py --json
```

Если файлы активной версии не совпадают с манифестом, сервис при выборе модели
пишет предупреждение в журнал, но продолжает работу. Версиям, зарегистрированным
до появления манифестов, они проставляются один раз:
`python tools/bootstrap_manifests.py`.

## Версии модели и откат

Каждая принятая модель регистрируется как версия в `ml/artifacts/versions.json`
(для организации — `ml/artifacts/<tenant>/versions.json`), а рабочий каталог
`sensitivity_feedback` наполняется жёсткими ссылками на файлы версии, поэтому
история не удваивает место на диске. Хранятся последние пять версий.

```bash
# посмотреть историю
python tools/rollback_model.py --list

# вернуться на предыдущую версию
python tools/rollback_model.py

# вернуться на конкретную версию организации
python tools/rollback_model.py --tenant org1 --to v20261112-094018
```

Каждый откат и каждое обучение пишутся в журнал `var/audit.jsonl`
(`kind: model_rollback` / `model_training`) и видны в панели в разделе аудита.

## Единый журнал состояния

Модель, правила и конфигурация меняются независимо, поэтому их можно зафиксировать
согласованно — одной записью в `var/state-history/journal.jsonl`:

```bash
python tools/state_history.py --capture --note "перед пилотом"
python tools/state_history.py --list
python tools/state_history.py --rollback s20261113-065958
python tools/state_history.py --rollback s20261113-065958 --with-config
```

Через панель:

```bash
curl -s http://localhost:8081/ui/state                                   # список
curl -X POST http://localhost:8081/ui/state/capture -d '{"note":"..."}'  # снимок
curl -X POST http://localhost:8081/ui/state/rollback -d '{"state":"s2026..."}'  # откат
```

Снимок содержит активную версию модели, копию `config/rules.json` с хешем и копию
конфигурации. Откат возвращает модель и правила, перезагружает классификатор и
пишется в аудит как `state_rollback`. Конфигурация восстанавливается только по
явному флагу `--with-config`, потому что содержит пути и настройки окружения.
Хранятся последние 20 состояний.

## Обратная связь и дообучение

Метки аналитика (подтверждение / ложное срабатывание) сохраняются в `var/labels/analyst_labels.jsonl`.

```bash
# 1. выгрузить датасет из меток
curl -s http://localhost:8081/ui/labels/export -o var/labels/dataset.jsonl

# 2. проверить, что данных достаточно
python tools/train_from_labels.py --input var/labels/dataset.jsonl --dry-run

# 3. дообучить и сравнить с текущей моделью
python tools/train_from_labels.py --input var/labels/dataset.jsonl
```

Скрипт делит набор на обучающую и отложенную выборки, дообучает модель от текущего
артефакта и сохраняет результат в `ml/artifacts/sensitivity_feedback` **только если**
выполнены оба условия: F1 на отложенной выборке не хуже текущего более чем на 0,02
и F1 на регрессионном наборе `ml/regression_set.jsonl` (235 путей с известными
классами) не упал более чем на 0,02. Иначе модель переименовывается в
`sensitivity_feedback.rejected` и в работу не попадает. Отчёт пишется в
`var/labels/training_report.json`.

Метки делятся на сильные и слабые: сильные — там, где аналитик указал верный класс
(`?strength=strong`), слабые — подтверждения без правки. Обучение идёт на сильных,
если их не меньше 20, иначе на всём наборе с предупреждением.

Чтобы применять принятую модель без правки конфигурации, задайте
`ml.artifact_path: "auto"` — сервис берёт активную версию из реестра
`ml/artifacts/versions.json` (каталоги `*.rejected` и старые версии не
используются). Переключить модель без перезапуска:

```bash
curl -X POST http://localhost:8081/ui/model/reload
# {"ok":true,"version":"v20261112-094018","artifact":"versions/v20261112-094018"}
```

После отката достаточно вызвать тот же адрес — сервис перечитает реестр.

### Версии правил

Перед каждой перезагрузкой правил сохраняется снимок в `var/rules-history/`
(последние 10). Список и откат:

```bash
curl http://localhost:8081/ui/rules/versions
curl -X POST http://localhost:8081/ui/rules/rollback \
     -H 'Content-Type: application/json' \
     -d '{"version": "rules-20261112-100207.json"}'
```

Обучение намеренно вынесено из сервиса: экземпляр только собирает разметку,
а обучение требует валидации и решения о промоушене артефакта.

## Доступ к изменяющим запросам

Ключи доступа разделены по ролям:

```json
{"http": {"api_key": "пишущий-ключ", "read_key": "читающий-ключ"}}
```

| Роль | Что может |
|---|---|
| читающий (`read_key`) | смотреть панель, события, выгрузки, аудит |
| пишущий (`api_key`) | всё то же плюс разметка, настройки, перезагрузка правил и модели, откат |

```bash
curl -X POST http://localhost:8081/ui/rules/reload -H "X-API-Key: $SIEM_WRITE_KEY"
curl -X POST http://localhost:8081/ui/rules/reload -H "X-API-Key: $SIEM_READ_KEY"
# {"detail": "требуется пишущий ключ (X-API-Key)"}
```

Ключ можно передать заголовком `X-API-Key` или один раз открыть панель по ссылке
`http://localhost:8081/ui?key=<читающий-ключ>` — сервис запомнит его в cookie.
Проверки состояния, готовности и метрики (`/healthz`, `/readyz`, `/metrics`)
открыты всегда, чтобы мониторинг не зависел от ключа. Сравнение выполняется в
постоянное время. Если ключи не заданы, сервис пишет предупреждение при старте:
режим без аутентификации допустим только в изолированном контуре.

## Форма события для `/v1/enrich`

Пути файлов распознаются в нескольких формах. Сильные ключи работают на верхнем
уровне, слабый `path` — только во вложенном файловом контексте:

```bash
# сильные ключи
curl -X POST http://localhost:8081/v1/enrich -H 'Content-Type: application/json' -d '{
  "event_id": "1", "ts": "2026-11-13T10:00:00Z", "action": "read",
  "user": "ivanov", "host": "ws-1",
  "filename": "C:\\Бухгалтерия\\Договор.docx"
}'

# вложенный файловый объект
curl -X POST http://localhost:8081/v1/enrich -H 'Content-Type: application/json' -d '{
  "event_id": "2", "ts": "2026-11-13T10:00:00Z", "action": "copy",
  "user": "ivanov", "host": "ws-1",
  "files": [{"path": "C:\\Бухгалтерия\\Договор.docx"}]
}'
```

Сильные ключи: `filename`, `filepath`, `fullpath`, `file_name`, `targetfilename`,
`objectname` и подобные. Слабые: `path`, `name`, `file`, `location` — они
учитываются только внутри файлового контекста (`files[]`, `file`, `object`).

Если передать `{"path": "C:\\...\\файл.docx"}` на верхнем уровне, путь будет
проигнорирован, класс останется `internal`, а `sensitivity_method` — `none`.
Это защита от ложных срабатываний на поле `path` в событиях сети и процессов.

## Поток событий для демонстрации

Три способа наполнить стенд:

**1. Кнопки в панели** (главное для показа):

- «▶ поток» — непрерывная подача событий, интервал 2 с;
- «■ стоп» — остановить поток;
- «+25 событий» — разовая порция.

Те же действия через API:

```bash
curl -s http://localhost:8081/ui/demo                                   # состояние
curl -X POST http://localhost:8081/ui/demo/start -d '{"interval":2}'    # запустить
curl -X POST http://localhost:8081/ui/demo/stop  -d '{}'                # остановить
curl -X POST http://localhost:8081/ui/demo/events -d '{"count":50}'     # порция
```

**2. Поток через Kafka** (полный путь: брокер → конвейер → приёмники):

```bash
PRODUCER_INTERVAL=3 PRODUCER_COUNT=10 docker compose --profile producer up -d producer-loop
docker compose stop producer-loop
```

**3. Разовый прогон генератора**:

```bash
docker compose --profile producer run --rm producer      # 120 событий

docker exec siem-enricher python /app/tools/generate_sample_events.py \
  --scenario ransomware --count 40 --out /tmp/night.jsonl
```

Сценарии генератора: `mixed`, `benign`, `ransomware`, `public`. Параметры потока:
`--interval` (пауза, секунды), `--repeat` (`0` — бесконечно).

## Нагрузочная проверка

Прогон через полный контур (Kafka → обогащение → Kafka/файл/webhook), 1000 событий:

| Конфигурация | Пропускная способность | Потери | Средняя задержка |
|---|---|---|---|
| Полный контур (3 приёмника, SQLite) | **17,7 соб/с** | 0 | 22,3 мс |
| Только файловый приёмник | **40,2 соб/с** | 0 | 17,3 мс |
| Provenance в памяти (без SQLite) | **43,8 соб/с** | 0 | 14,0 мс |

Медиана обогащения — 5 мс, p95 — 100 мс, p99 — 250 мс. Потерь нет ни в одной
конфигурации: смещения фиксируются только после успешной доставки.

Узкое место — синхронная запись в приёмники и SQLite, а не классификация:
в памяти без приёмников конвейер даёт 459 соб/с.

```bash
bash tools/load_wait_run.sh            # 1000 событий, отчёт в var/load_report.json
bash tools/load_matrix.sh              # три конфигурации подряд
```

Пути ускорения: пакетная отправка в приёмники, `acks=1` вместо `all`,
асинхронная запись provenance. Оценка: ×3–6 к текущему значению.

## Качество и ограничения

- **227 автотестов**, покрытие по строкам — **76 %** (измерено `coverage`).
- `ruff` без замечаний, CI на Python 3.11 и 3.12, проверка валидности конфигурации.
- HTTP: ограничение тела запроса 2 МБ (`413`), пакет не более 500 событий (`422`),
  ключи доступа на изменяющие операции, чтение защищается отдельным ключом.

### Сценарий инцидента для демонстрации

Кнопка **«инцидент»** в настройках панели добавляет связную цепочку из шести
событий одного пользователя: чтение зарплатной ведомости, упаковка в архив,
копирование на съёмный носитель, отправка на внешний ресурс, пересылка почтой,
удаление архива. Цепочка воспроизводит расследование: глубина происхождения 5,
внешние адресаты, решение о блокировке.

```bash
curl -X POST http://localhost:8081/ui/demo/events -d '{"scenario": "incident"}'
```

## Состав (7 модулей)

| № | Модуль | Код |
|---|---|---|
| 1 | Коннектор к SIEM — подписка на поток (Kafka; файл/Elasticsearch — дополнительно) | `src/siem_enricher/connectors/` |
| 2 | Извлекатель метаданных (файлы, пути, процессы, пользователи, адреса, правило) | `src/siem_enricher/extractor/` |
| 3 | ML-классификатор конфиденциальности (гибрид: модель + правила) | `src/siem_enricher/ml/`, `ml/` |
| 4 | Модуль provenance (граф и цепочки происхождения) | `src/siem_enricher/provenance/` |
| 5 | Обогатитель (сборка результата, риск-скоринг) | `src/siem_enricher/enricher/` |
| 6 | Модуль применения политик (маскирование, алертинг, блокировка) | `src/siem_enricher/policy/` |
| 7 | Обратный коннектор в SIEM | `src/siem_enricher/connectors/` |

Дополнительно: HTTP-сервис (`service/`), CLI (`cli.py`), метрики Prometheus (`metrics.py`),
журнал аудита (`audit.py`).

## Быстрый старт (без инфраструктуры)

Ядро работает на стандартной библиотеке Python 3.11+, поэтому демонстрация не требует
Kafka, базы данных и интернета.

```powershell
# 1. Проверить ядро на синтетическом потоке (18 проверок)
python tools\smoke_pipeline.py --config config\config.local.json
python tools\smoke_pipeline.py --config config\config.local.json --force-heuristic   # без ML

# 2. Сгенерировать события и обогатить их
python tools\generate_sample_events.py --scenario mixed --count 120 --out var\generated.jsonl
python -m siem_enricher replay --config config\config.local.json `
    --input var\generated.jsonl --output var\enriched_events.jsonl

# 3. Отдельные операции
python -m siem_enricher classify --config config\config.local.json `
    --path "C:\keys\id_rsa" --path "C:\HR\Зарплатная_ведомость_2025.xlsx" `
    --path "C:\Public\Шаблон_письма_клиенту.docx"
python -m siem_enricher chain --config config\config.local.json `
    --path "E:\Копия_Зарплатная_ведомость_2025.xlsx"

# 4. Тесты
python -m unittest discover -s tests -t .
```

## Быстрый старт (боевой профиль и стенд)

```powershell
pip install -e ".[service,kafka,config,http]"   # сервис
pip install -r requirements-ml.txt              # + torch (CPU) и transformers для ML

python -m siem_enricher validate-config --config config\config.example.json
python -m siem_enricher run     --config config\config.example.json   # Kafka -> обогащение -> Kafka
python -m siem_enricher serve   --config config\config.example.json   # HTTP API + /metrics
```

```bash
docker compose up --build                  # kafka + enricher + redis + заглушка SIEM
docker compose --profile producer up       # публикация 120 синтетических событий в Kafka
docker compose --profile observability up  # + Prometheus (9090) и Grafana (3000)
```

## ML-контур

* модель из НИР: `bert-base-multilingual-cased`, 6 категорий (`personal`, `banking`, `commercial`,
  `ip`, `official_internal`, `public`), обучение на **именах файлов**;
* артефакт: `ml/artifacts/sensitivity_transformer/` (`config.json`, `model.safetensors`,
  `tokenizer.json`, `label_encoder.pkl`, `metrics.json`); в git не хранится (~680 МБ);
* гибридная схема: признаки размещения и пометок (каталог `keys/`, `HR/`, `Public/`, гриф, `.kdbx`,
  `.pem`) имеют приоритет над прогнозом модели;
* отображение категорий на классы и веса риска — `config/sensitivity_labels.json`;
* обучение и оценка: `ml/training/build_dataset.py`, `train_transformer.py`,
  `evaluate_transformer.py`, `train_sklearn.py` (см. `ml/README.md`).

Без модели (или без `torch`) сервис работает на детерминированных правилах и не теряет события —
причина фиксируется в метрике `siem_enricher_ml_fallback_total`.

## Профили конфигурации

| Файл | Источник | Приёмник | Provenance |
|---|---|---|---|
| `config/config.local.json` | файловый реплей | файл JSONL | память |
| `config/config.example.json` | Kafka | Kafka | SQLite |
| `config/config.docker.json` | Kafka | Kafka + файл + webhook | SQLite/Redis |

Правила политик — `config/policies.json` (9 правил: утечка, секреты, массовый доступ,
архивирование, insider-доступ, съёмный носитель, ransomware, длинная цепочка, «белое» правило).

## Проверено

| Проверка | Результат |
|---|---|
| Модульные и интеграционные тесты | **152 теста, все проходят** (3 теста модели требуют torch) |
| Сквозной сценарий `tools/smoke_pipeline.py` | **18 из 18** проверок, с ML и без ML |
| Классы конфиденциальности на синтетическом потоке | гибрид **0.772** против **0.463** у модели без правил |
| Категории модели на «родном» датасете | accuracy **0.952**, F1 macro 0.949 (1599 имён) |
| Задержка обогащения | ≈ 148 мс/событие с mBERT (CPU), ≈ 128 мс без ML |
| Срабатывания правил на 15 событий | 21 (все 9 правил проверены на своих сценариях) |
| HTTP-интерфейс (9 эндпоинтов) | смоук `scripts/http_smoke.ps1`: все отвечают, сервис стартует за 1,5 с |

Подробности и условия измерений — `docs/05-ml-классификатор.md`, `docs/09-тестирование-и-метрики.md`.

## Документация

| Документ | Содержание |
|---|---|
| [docs/00-глоссарий-и-обзор.md](docs/00-глоссарий-и-обзор.md) | термины, место в конвейере SIEM, границы ПС |
| [docs/01-архитектура.md](docs/01-архитектура.md) | компоненты, поток данных, обоснование решений, отказоустойчивость |
| [docs/02-план-работ.md](docs/02-план-работ.md) | этапы, план-график, контрольные точки, вопросы на защите |
| [docs/03-структура-проекта.md](docs/03-структура-проекта.md) | карта каталогов с назначением файлов |
| [docs/04-модель-данных.md](docs/04-модель-данных.md) | каноническое событие, поля обогащения, формула риска, пример «до/после» |
| [docs/05-ml-классификатор.md](docs/05-ml-классификатор.md) | модель, гибрид, метрики, анализ ошибок, развитие |
| [docs/06-provenance.md](docs/06-provenance.md) | граф происхождения, хранилища, ограничения |
| [docs/07-политики-и-действия.md](docs/07-политики-и-действия.md) | DSL правил, действия, режимы, аудит, ограничение маскирования |
| [docs/08-развертывание.md](docs/08-развертывание.md) | установка, Docker/K8s, метрики, диагностика, производительность |
| [docs/09-тестирование-и-метрики.md](docs/09-тестирование-и-метрики.md) | состав тестов, методика измерений, границы покрытия |
| [docs/10-соответствие-вкр.md](docs/10-соответствие-вкр.md) | привязка к главам ВКР, таблицы, сценарий демонстрации |
| [docs/11-риски-и-ограничения.md](docs/11-риски-и-ограничения.md) | 12 ограничений ПС, риски проекта, направления развития |

## Статус

Реализованы и проверены: конвейер обогащения (извлечение → ML → provenance → риск → политики),
коннекторы Kafka/файл/webhook (Elasticsearch и Wazuh Indexer — необязательные примеры),
HTTP API, CLI, метрики Prometheus, журнал аудита, Docker/K8s-развёртывание, ML-контур
с дообучением и оценкой, 152 теста и сквозной сценарий.

Проверено: HTTP-слой FastAPI (смоук по всем эндпоинтам, `scripts/http_smoke.ps1`) и стенд
с открытой SIEM (профиль `siem` в compose: OpenSearch + засев индекса + обогащение потока).
Живые интеграции с Kafka и Elasticsearch требуют брокера/кластера и проверяются на стенде:
`docker compose --profile siem up --build`, команды — в `docs/08-развертывание.md`.

# siem-enricher — сервис обогащения событий SIEM

Программное средство для ВКР: сервис, который встраивается в конвейер обработки событий SIEM
и дополняет каждое событие сведениями, которых в нём нет:

| Поле | Смысл | Кто считает |
|---|---|---|
| `data_sensitivity` | класс конфиденциальности объекта (`public` → `secret`) | ML-модель (mBERT по имени файла) + правила по каталогу и пометкам |
| `provenance_chain` | цепочка происхождения: чтение → копирование → архивирование → отправка | модуль provenance |
| `risk_score`, `risk_severity` | оценка риска 0…1 и уровень критичности | риск-скоринг |
| `policy_actions` | сработавшие правила и выполненные действия (маскирование, алерт, блокировка) | модуль политик |

Обогащённые события возвращаются в SIEM (Kafka) для корреляции и реагирования.

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
| Модульные и интеграционные тесты | **121 тест, все проходят** (3 теста модели требуют torch) |
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
с дообучением и оценкой, 121 тест и сквозной сценарий.

Проверено: HTTP-слой FastAPI (смоук по всем эндпоинтам, `scripts/http_smoke.ps1`) и стенд
с открытой SIEM (профиль `siem` в compose: OpenSearch + засев индекса + обогащение потока).
Живые интеграции с Kafka и Elasticsearch требуют брокера/кластера и проверяются на стенде:
`docker compose --profile siem up --build`, команды — в `docs/08-развертывание.md`.

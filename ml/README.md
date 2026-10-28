# ML-контур: датасет, обучение, оценка, подключение к сервису

Каталог описывает, как получить и сопровождать модель классификации конфиденциальности,
которая используется сервисом-обогатителем.

## Что подаётся на вход модели

Модель классифицирует **имя файла** (короткий текст). Это принципиально: она обучена
на 1600 примерах вида `паспорт_иванова_4512345678.jpg`, `dogovor_KT_romashka.docx`
(``max_length=64``), и именно так подаётся вход при инференсе
(``config/config.*.json`` -> ``ml.text_template = "{name}"``).

Каталог размещения, расширение и действие над файлом учитывает **гибридный слой**
(``siem_enricher.ml.hybrid``) и модуль provenance — см. `docs/05-ml-классификатор.md`.

## Формат артефакта

### Трансформер (основной режим)

Каталог чекпоинта HuggingFace, который сохраняет `train_transformer.py`:

| Файл | Назначение |
|---|---|
| `config.json` | архитектура (`BertForSequenceClassification`) и число классов |
| `model.safetensors` | веса модели |
| `tokenizer.json`, `tokenizer_config.json` | токенизатор |
| `label_encoder.pkl` | `sklearn.LabelEncoder`: индекс -> категория |
| `metrics.json` | метрики на отложенной выборке (для отчёта ВКР) |

Сервис загружает его так:

```json
"ml": {
  "type": "hybrid",
  "artifact_path": "ml/artifacts/sensitivity_transformer",
  "label_encoder_file": "label_encoder.pkl",
  "max_length": 64,
  "device": "auto"
}
```

### Признаковая модель (альтернатива)

`train_sklearn.py` сохраняет joblib-артефакт для узлов без torch:

```json
"ml": { "type": "sklearn", "artifact_path": "ml/artifacts/sensitivity_sklearn.joblib" }
```

## Категории модели и классы конфиденциальности

Модель предсказывает 6 категорий, которые отображаются на 4 класса
(таблица — `config/sensitivity_labels.json`, раздел `model_categories`):

| Категория модели | Класс | Пояснение |
|---|---|---|
| `personal` | confidential | персональные данные |
| `banking` | confidential | банковская тайна |
| `commercial` | confidential | коммерческая тайна |
| `ip` | confidential | интеллектуальная собственность, ноу-хау |
| `official_internal` | internal | для служебного пользования |
| `public` | public | открытая информация |

Класс `secret` присваивается **только детерминированными правилами** (`id_rsa`, `.kdbx`,
`.pem`, `.env`, каталоги `keys/`, `secrets/`) — такого класса в модели нет.

## Порядок работы

```powershell
# 1. Датасет: из синтетического генератора и/или из CSV формата НИР (text,label)
python ml\training\build_dataset.py --from-csv C:\путь\filenames_mixed_dataset.csv `
    --out ml\data\processed\files.csv

# 2. Дообучение (нужны torch + transformers: pip install -r requirements-ml.txt)
python ml\training\train_transformer.py --dataset ml\data\processed\files.csv `
    --output ml\artifacts\sensitivity_transformer --epochs 5

# 3. Оценка качества (метрики категорий и классов конфиденциальности)
python ml\training\evaluate_transformer.py --model ml\artifacts\sensitivity_transformer `
    --dataset ml\data\processed\files.csv --output var\metrics_transformer.json

# 4. Проверка в сервисе
python tools\smoke_pipeline.py --config config\config.local.json
```

## Структура каталога

| Путь | Назначение |
|---|---|
| `ml/artifacts/sensitivity_transformer/` | текущая модель (в git не хранится, ~680 МБ) |
| `ml/data/raw/` | исходные выгрузки (в git не хранятся) |
| `ml/data/interim/` | промежуточные чекпоинты обучения |
| `ml/data/processed/files.csv` | готовый датасет `path,text,label` |
| `ml/training/build_dataset.py` | сборка датасета из генератора и CSV |
| `ml/training/train_transformer.py` | дообучение трансформера |
| `ml/training/evaluate_transformer.py` | метрики качества |
| `ml/training/train_sklearn.py` | модель на признаках пути (без torch) |
| `ml/notebooks/` | место для исследовательских ноутбуков |

## Воспроизводимость

* во всех скриптах фиксируется `--seed` (по умолчанию 42);
* метрики сохраняются в JSON и прикладываются к ВКР;
* версия модели попадает в обогащённое событие (`sensitivity_model_version`), поэтому
  по журналу обогащения можно понять, какой моделью получен класс.

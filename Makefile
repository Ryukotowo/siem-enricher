# Основные операции проекта (Windows: см. scripts\*.ps1)
PY ?= python
PKG := src/siem_enricher
CONFIG ?= config/config.local.json
PYTEST ?= $(PY) -m pytest

.PHONY: help install install-ml install-dev fmt lint typecheck test test-pytest smoke smoke-heuristic \
        generate replay validate classify serve run docker-build docker-up docker-down clean

help: ## Показать список целей
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Установить сервис с боевыми зависимостями
	$(PY) -m pip install -e ".[service,kafka,config,http,es]"

install-ml: ## Установить ML-зависимости (torch CPU + transformers)
	$(PY) -m pip install -r requirements-ml.txt

install-dev: ## Установить сервис с зависимостями разработки
	$(PY) -m pip install -e ".[all,dev]"

fmt: ## Форматирование (ruff + black)
	ruff check --fix $(PKG) tests tools || true
	black $(PKG) tests tools || true

lint: ## Статический анализ
	ruff check $(PKG) tests tools ml

typecheck: ## Проверка типов
	mypy

test: ## Тесты на стандартной библиотеке (без внешних зависимостей)
	$(PY) -m unittest discover -s tests -t .

test-pytest: ## Тесты через pytest (с покрытием)
	$(PYTEST) --cov=$(PKG) --cov-report=term-missing

smoke: ## Сквозной сценарий с моделью (если доступна)
	$(PY) tools/smoke_pipeline.py --config $(CONFIG)

smoke-heuristic: ## Сквозной сценарий только на правилах
	$(PY) tools/smoke_pipeline.py --config $(CONFIG) --force-heuristic

generate: ## Сгенерировать синтетические события
	$(PY) tools/generate_sample_events.py --scenario mixed --count 120 --out var/generated.jsonl

replay: ## Обогатить файл событий
	$(PY) -m siem_enricher replay --config $(CONFIG) \
		--input var/generated.jsonl --output var/enriched_events.jsonl

validate: ## Проверить конфигурацию и правила
	$(PY) -m siem_enricher validate-config --config $(CONFIG)

classify: ## Классифицировать пример набора объектов
	$(PY) -m siem_enricher classify --config $(CONFIG) \
		--path "C:\keys\id_rsa" --path "C:\HR\Зарплатная_ведомость_2025.xlsx" \
		--path "C:\Public\Шаблон_письма_клиенту.docx"

serve: ## Запустить HTTP-сервис обогащения
	$(PY) -m siem_enricher serve --config $(CONFIG) --port 8080

run: ## Запустить конвейер источник -> обогатитель -> приёмник
	$(PY) -m siem_enricher run --config $(CONFIG)

docker-build: ## Собрать образ (без ML: --build-arg INSTALL_ML=0)
	docker build -t siem-enricher:0.1.0 .

docker-up: ## Поднять демонстрационный стенд
	docker compose up --build -d

docker-down: ## Остановить стенд
	docker compose down

clean: ## Очистить артефакты выполнения
	rm -rf var/logs/*.jsonl var/state/*.db var/enriched_events.jsonl .pytest_cache htmlcov .coverage

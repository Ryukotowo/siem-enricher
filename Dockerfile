# Образ сервиса-обогатителя событий SIEM (источник и приёмник — Kafka).
#
# Сборка с ML-моделью (по умолчанию) добавляет torch CPU + transformers (~1.2 ГБ).
# Чтобы собрать «лёгкий» образ только с детерминированными правилами:
#     docker build --build-arg INSTALL_ML=0 -t siem-enricher:0.1.0 .
#
# Веса модели в образ НЕ копируются: каталог ml/artifacts монтируется как том
# (см. docker-compose.yml), чтобы не раздувать образ и репозиторий.
FROM python:3.12-slim

ARG INSTALL_ML=1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    TOKENIZERS_PARALLELISM=false

# curl нужен для HEALTHCHECK
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Зависимости — отдельный слой, кэшируется при изменении только кода
COPY requirements.txt requirements-ml.txt ./
RUN pip install -r requirements.txt \
    && if [ "$INSTALL_ML" = "1" ]; then pip install -r requirements-ml.txt; fi

# 2) Код, конфигурация и инструменты
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY tools ./tools
COPY deploy ./deploy
RUN pip install --no-deps -e . && chmod +x /app/deploy/docker/docker-entrypoint.sh

# 3) Непривилегированный пользователь; каталоги состояния и модели — точки монтирования
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin enricher \
    && mkdir -p /app/var/logs /app/var/state /app/ml/artifacts \
    && chown -R enricher:enricher /app/var /app/ml
USER 10001

EXPOSE 8080 9101

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/deploy/docker/docker-entrypoint.sh"]

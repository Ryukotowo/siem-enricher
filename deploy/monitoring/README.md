# Мониторинг: Prometheus + Grafana

Сервис отдаёт метрики в формате Prometheus по адресу `/metrics`
(порт задаётся при запуске `serve --port`).

## Запуск

```bash
# 1. сервис на хосте
python -m siem_enricher serve --config config/config.local.json --port 8080

# 2. мониторинг
cd deploy/monitoring
docker compose up -d
```

| Адрес | Что смотреть |
|---|---|
| http://localhost:9090 | Prometheus, проверка таргета `siem-enricher` |
| http://localhost:3000 | Grafana, вход `admin` / `admin`, дашборд «siem-enricher» |

Дашборд подключается автоматически через provisioning — искать в списке
дашбордов «siem-enricher».

## Что на дашборде

| Панель | Метрика |
|---|---|
| Поток событий и обогащение | `rate(siem_enricher_events_consumed_total[1m])`, `..._enriched_total` |
| Решения политик | `sum by (decision) (siem_enricher_policy_decisions_total)` |
| Задержка p50 / p95 / p99 | `histogram_quantile(...)` по `enrichment_duration_seconds_bucket` |
| Классы конфиденциальности | `sum by (level) (rate(siem_enricher_sensitivity_classified_total[5m]))` |
| Доля попаданий в кэш | `cache_hits / (cache_hits + cache_misses)` |
| Метки и изменения настроек | `analyst_labels_total`, `config_changes_total` |

## Если сервис в контейнере

В `prometheus.yml` замените таргет на имя контейнера сервиса и убедитесь,
что оба контейнера в одной сети:

```yaml
- targets: ["siem-enricher:8080"]
```

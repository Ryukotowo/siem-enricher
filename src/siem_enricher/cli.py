"""Интерфейс командной строки сервиса обогащения событий SIEM."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from siem_enricher.config import AppConfig, ConfigError, load_config
from siem_enricher.connectors import available_sinks, available_sources
from siem_enricher.logging_setup import get_logger, setup_logging
from siem_enricher.ml import build_classifier, load_label_weights
from siem_enricher.policy import load_rules, validate_rules
from siem_enricher.provenance import ProvenanceBuilder, build_store
from siem_enricher.service.runtime import EnrichmentRuntime, build_runtime
from siem_enricher.version import ENRICHMENT_SCHEMA_VERSION, VERSION

logger = get_logger("cli")

DEFAULT_CONFIG = "config/config.example.json"




def _prepare_logging(args: argparse.Namespace, config: AppConfig | None = None) -> None:
    level = getattr(args, "log_level", None) or (config.service.log_level if config else "INFO")
    fmt = getattr(args, "log_format", None) or (config.service.log_format if config else "json")
    setup_logging(
        level=level,
        fmt="human" if getattr(args, "human_logs", False) else fmt,
        service=config.service.name if config else "siem-enricher",
        instance=config.service.instance_id if config else "cli",
    )


def _load(args: argparse.Namespace) -> AppConfig:
    return load_config(args.config)


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _print_table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> None:
    """Простой вывод таблицы без внешних зависимостей."""
    if not rows:
        print("(нет данных)")
        return
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    line = "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-" * len(line))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def _print_replay_summary(summary: dict[str, Any]) -> None:
    print()
    print("=== Итоги обогащения ===")
    _print_table(
        [
            ["Обработано событий", summary.get("processed", 0)],
            ["Ошибок", summary.get("failed", 0)],
            ["Время, с", summary.get("elapsed_seconds", 0)],
            ["Скорость, соб/с", summary.get("throughput_per_second", 0)],
            ["Средняя задержка, мс", summary.get("mean_duration_ms", 0)],
            ["Режим политик", summary.get("policy_mode", "")],
            ["Итоговое решение", summary.get("policy_decision", "")],
        ],
        ("Показатель", "Значение"),
    )
    print()
    print("Распределение по классам конфиденциальности:")
    _print_table(sorted((summary.get("sensitivity_levels") or {}).items()), ("Класс", "Событий"))
    print()
    print("Распределение по уровням риска:")
    _print_table(sorted((summary.get("risk_severities") or {}).items()), ("Уровень", "Событий"))
    print()
    print("Сработавшие правила:")
    _print_table(sorted((summary.get("triggered_rules") or {}).items()), ("Правило", "Срабатываний"))


def _cmd_version(args: argparse.Namespace) -> int:
    _print_json(
        {
            "service": "siem-enricher",
            "version": VERSION,
            "schema_version": ENRICHMENT_SCHEMA_VERSION,
            "sources": available_sources(),
            "sinks": available_sinks(),
        }
    )
    return 0


def _cmd_connectors(args: argparse.Namespace) -> int:
    _print_table([["источники", ", ".join(available_sources())],
                  ["приёмники", ", ".join(available_sinks())]], ("Группа", "Типы"))
    return 0


def _cmd_validate_config(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    problems: list[str] = []

    config_errors = config.validate()
    problems.extend(f"конфигурация: {error}" for error in config_errors)

    if config.source.type not in available_sources():
        problems.append(f"неизвестный источник {config.source.type!r}; доступны: {available_sources()}")
    if config.sink.type not in available_sinks():
        problems.append(f"неизвестный приёмник {config.sink.type!r}; доступны: {available_sinks()}")

    policy_path = Path(args.policies) if args.policies else config.policy_path
    if policy_path.exists():
        try:
            rules = load_rules(policy_path)
            problems.extend(f"правила: {problem}" for problem in validate_rules(rules))
            print(f"Загружено правил: {len(rules)} (файл {policy_path})")
        except ConfigError as exc:
            problems.append(f"правила: {exc}")
    else:
        problems.append(f"файл правил не найден: {policy_path}")

    if not config.labels_path.exists():
        problems.append(f"реестр классов не найден: {config.labels_path}")
    else:
        weights = load_label_weights(config.labels_path)
        print(f"Классы конфиденциальности: {', '.join(sorted(weights)) or 'нет данных'}")

    try:
        classifier = build_classifier(config.ml)
        print(f"Классификатор: {classifier.describe()}")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"классификатор: {exc}")

    try:
        store = build_store(config.provenance)
        print(f"Хранилище provenance: {store.stats()}")
        store.close()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"хранилище provenance: {exc}")

    if problems:
        print()
        print("Обнаружены проблемы:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print()
    print("Конфигурация корректна.")
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    classifier = build_classifier(config.ml)
    assessments = classifier.predict_many(args.path)
    if args.json:
        _print_json([assessment.to_dict() for assessment in assessments])
        return 0
    print(f"Классификатор: {classifier.describe()}")
    _print_table(
        [
            [a.level.value, a.level.ru, f"{a.confidence:.2f}", a.method, a.target]
            for a in assessments
        ],
        ("Класс", "Расшифровка", "Уверенность", "Метод", "Объект"),
    )
    return 0


def _cmd_chain(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    store = build_store(config.provenance)
    builder = ProvenanceBuilder.from_config(config.provenance, store)
    try:
        chain = builder.chain_for(args.path)
    finally:
        store.close()
    if args.json:
        _print_json(chain.to_dict())
        return 0
    print(f"Цепочка происхождения: {chain.file_path}")
    print(f"Глубина: {chain.depth}; внешние адреса: {chain.external_endpoints or 'нет'}")
    _print_table(
        [
            [
                step.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                step.action.value,
                step.direction,
                step.actor_user or step.actor_process or "-",
                step.counterpart_path or step.endpoint or "-",
            ]
            for step in chain.steps
        ],
        ("Время", "Действие", "Направление", "Субъект", "Связанный объект"),
    )
    return 0


async def _run_pipeline(runtime: EnrichmentRuntime, max_events: int | None) -> dict[str, Any]:
    """Запустить конвейер с обработкой сигналов завершения."""
    loop = asyncio.get_running_loop()

    def _request_stop(*_: Any) -> None:
        runtime.request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):  # Windows
            try:
                signal.signal(sig, _request_stop)
            except (ValueError, OSError):  # не главный поток
                pass
    return await runtime.run(max_events=max_events)


def _cmd_run(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    runtime = build_runtime(config)
    try:
        stats = asyncio.run(_run_pipeline(runtime, args.max_events))
    except KeyboardInterrupt:  # pragma: no cover - ручное прерывание
        print("Остановлено пользователем")
        return 130
    finally:
        runtime.close()
    _print_json(stats)
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    runtime = build_runtime(config)
    try:
        summary = asyncio.run(
            runtime.replay(
                input_path=args.input,
                output_path=args.output,
                limit=args.limit,
                apply_policies=not args.no_policies,
                collect_documents=args.json,
            )
        )
    finally:
        runtime.close()
    if args.json:
        _print_json(summary)
    elif not getattr(args, "quiet", False):
        _print_replay_summary(summary)
    return 0 if not summary.get("failed") else 1


def _cmd_serve(args: argparse.Namespace) -> int:
    config = _load(args)
    _prepare_logging(args, config)
    from siem_enricher.service.app import serve

    serve(
        config,
        host=args.host,
        port=args.port,
        run_pipeline=args.run_pipeline,
        log_level=args.log_level,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem-enricher",
        description="Сервис обогащения событий SIEM: конфиденциальность, provenance, риск, политики",
    )
    parser.add_argument("--version", action="version", version=f"siem-enricher {VERSION}")
    parser.add_argument("--log-level", default=None, help="Уровень логирования (INFO, DEBUG, ...)")
    parser.add_argument("--human-logs", action="store_true", help="Читаемый формат логов вместо JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Запустить конвейер источник -> обогатитель -> приёмник")
    run_parser.add_argument("--config", default=DEFAULT_CONFIG)
    run_parser.add_argument("--max-events", type=int, default=None, help="Остановиться после N событий")
    run_parser.set_defaults(handler=_cmd_run)

    replay_parser = subparsers.add_parser("replay", help="Однократно обогатить файл событий")
    replay_parser.add_argument("--config", default=DEFAULT_CONFIG)
    replay_parser.add_argument("--input", required=True, help="Файл событий (JSONL/JSON)")
    replay_parser.add_argument("--output", default=None, help="Куда записать обогащённые события")
    replay_parser.add_argument("--limit", type=int, default=None, help="Обработать не более N событий")
    replay_parser.add_argument("--no-policies", action="store_true", help="Не применять политики")
    replay_parser.add_argument("--json", action="store_true", help="Вывести итоги в формате JSON")
    replay_parser.add_argument("--quiet", action="store_true", help="Не печатать сводку")
    replay_parser.set_defaults(handler=_cmd_replay)

    serve_parser = subparsers.add_parser("serve", help="Запустить HTTP-сервис обогащения")
    serve_parser.add_argument("--config", default=DEFAULT_CONFIG)
    serve_parser.add_argument("--host", default=None)
    serve_parser.add_argument("--port", type=int, default=None)
    serve_parser.add_argument("--run-pipeline", action="store_true", help="Читать поток источника вместе с сервисом")
    serve_parser.set_defaults(handler=_cmd_serve)

    classify_parser = subparsers.add_parser("classify", help="Классифицировать конфиденциальность путей")
    classify_parser.add_argument("--config", default=DEFAULT_CONFIG)
    classify_parser.add_argument("--path", action="append", required=True, help="Путь (можно указать несколько раз)")
    classify_parser.add_argument("--json", action="store_true")
    classify_parser.set_defaults(handler=_cmd_classify)

    chain_parser = subparsers.add_parser("chain", help="Показать цепочку происхождения файла")
    chain_parser.add_argument("--config", default=DEFAULT_CONFIG)
    chain_parser.add_argument("--path", required=True)
    chain_parser.add_argument("--json", action="store_true")
    chain_parser.set_defaults(handler=_cmd_chain)

    validate_parser = subparsers.add_parser("validate-config", help="Проверить конфигурацию и правила")
    validate_parser.add_argument("--config", default=DEFAULT_CONFIG)
    validate_parser.add_argument("--policies", default=None, help="Файл правил (по умолчанию из конфигурации)")
    validate_parser.add_argument("--quiet", action="store_true")
    validate_parser.set_defaults(handler=_cmd_validate_config)

    connectors_parser = subparsers.add_parser("connectors", help="Список доступных коннекторов")
    connectors_parser.set_defaults(handler=_cmd_connectors)

    version_parser = subparsers.add_parser("version", help="Версия сервиса и состав модулей")
    version_parser.set_defaults(handler=_cmd_version)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Файл не найден: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:  # pragma: no cover
        return 130


__all__ = ["build_parser", "main"]

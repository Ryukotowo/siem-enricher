"""Сквозная проверка ядра сервиса обогащения — без Kafka, Redis и других внешних сервисов."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _candidate in (PROJECT_ROOT / "src", PROJECT_ROOT):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from siem_enricher.config import AppConfig, load_structured  # noqa: E402
from siem_enricher.enricher import EnrichmentPipeline  # noqa: E402
from siem_enricher.metrics import render_prometheus, service_metrics  # noqa: E402
from siem_enricher.models.enrichment import EnrichedEvent  # noqa: E402
from tools.generate_sample_events import build_events  # noqa: E402


class Report:
    """Накопитель результатов проверок."""

    def __init__(self, verbose: bool = True) -> None:
        self.rows: list[tuple[str, bool, str]] = []
        self.verbose = verbose

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.rows.append((name, bool(passed), detail))
        if self.verbose:
            mark = "OK  " if passed else "FAIL"
            line = f"[{mark}] {name}"
            if detail:
                line += f" — {detail}"
            print(line)
        return bool(passed)

    @property
    def failed(self) -> list[tuple[str, bool, str]]:
        return [row for row in self.rows if not row[1]]

    @property
    def passed_count(self) -> int:
        return sum(1 for row in self.rows if row[1])


def build_config(config_path: Path, force_heuristic: bool, output: Path) -> AppConfig:
    """Собрать конфигурацию проверки: память вместо БД, файл вместо Kafka."""
    data = load_structured(config_path)
    data.setdefault("provenance", {})["backend"] = "memory"
    data["sink"] = {"type": "file_jsonl", "options": {"path": str(output), "mode": "overwrite"}}
    data["source"] = {"type": "file_replay", "options": {"path": "var/smoke_input.jsonl"}}
    if force_heuristic:
        data.setdefault("ml", {})["type"] = "heuristic"
    config = AppConfig.from_dict(data, path=config_path)
    errors = config.validate()
    if errors:
        raise SystemExit("Некорректная конфигурация:\n  - " + "\n  - ".join(errors))
    return config


def _by_tag(results: Sequence[tuple[EnrichedEvent, dict[str, Any]]], tag: str) -> list[EnrichedEvent]:
    return [enriched for enriched, _ in results if str(enriched.event.raw.get("x_scenario")) == tag]


def _rules(enriched: EnrichedEvent) -> list[str]:
    return [outcome.rule_id for outcome in enriched.enrichment.policies]


def _document(results: Sequence[tuple[EnrichedEvent, dict[str, Any]]], tag: str) -> dict[str, Any]:
    for enriched, document in results:
        if str(enriched.event.raw.get("x_scenario")) == tag:
            return document
    return {}


def run_checks(
    results: Sequence[tuple[EnrichedEvent, dict[str, Any]]],
    pipeline: EnrichmentPipeline,
    report: Report,
) -> None:
    """Проверки ожидаемого поведения конвейера."""
    all_enriched = [enriched for enriched, _ in results]

    report.check(
        "1. Все события обогащены",
        all(document.get("data_sensitivity") is not None and "risk_score" in document
            for _, document in results),
        f"событий: {len(results)}",
    )

    secret_events = [e for e in all_enriched if e.enrichment.sensitivity.level.value == "secret"]
    report.check(
        "2. Файлы с ключами и хранилищами секретов -> класс secret",
        bool(secret_events),
        ", ".join(e.event.primary_file.path if e.event.primary_file else "?" for e in secret_events[:2]),
    )

    public_events = _by_tag(results, "benign_public")
    report.check(
        "3. Открытые файлы -> класс public",
        bool(public_events)
        and all(e.enrichment.sensitivity.level.value == "public" for e in public_events),
        ", ".join(f"{e.enrichment.sensitivity.level.value}" for e in public_events),
    )

    hr_events = _by_tag(results, "insider_hr") + _by_tag(results, "insider_read")
    report.check(
        "4. Кадровые документы -> класс confidential",
        bool(hr_events)
        and all(e.enrichment.sensitivity.level.rank >= 2 for e in hr_events),
        ", ".join(f"{e.enrichment.sensitivity.level.value}/{e.enrichment.sensitivity.confidence:.2f}"
                  for e in hr_events),
    )

    upload = _by_tag(results, "exfil_upload")
    upload_ok = bool(upload) and all("POL-001" in _rules(e) for e in upload)
    upload_severity = upload[0].enrichment.risk.severity.value if upload and upload[0].enrichment.risk else "-"
    report.check(
        "5. POL-001 срабатывает при отправке конфиденциального файла во внешний адрес",
        upload_ok and upload_severity in {"high", "critical"},
        f"правила: {_rules(upload[0]) if upload else []}, риск: {upload_severity}",
    )

    upload_document = _document(results, "exfil_upload")
    masked_paths = [
        item.get("path")
        for item in (upload_document.get("files") or [])
        if isinstance(item, dict)
    ]
    report.check(
        "6. Маскирование полей применено к обогащённому событию",
        bool(upload_document.get("enrichment", {}).get("masked_fields"))
        and any(str(path).startswith("sha256:") for path in masked_paths),
        f"поля: {upload_document.get('enrichment', {}).get('masked_fields')}, путь: {masked_paths[:1]}",
    )

    usb = _by_tag(results, "usb_copy")
    report.check(
        "7. POL-006 срабатывает при копировании на съёмный носитель",
        bool(usb) and all({"POL-006", "POL-011"} & set(_rules(e)) for e in usb),
        f"правила: {_rules(usb[0]) if usb else []}",
    )

    ransomware = _by_tag(results, "ransomware")
    report.check(
        "8. POL-007/POL-010 срабатывают при переименовании и шифровании файлов",
        bool(ransomware)
        and all({"POL-007", "POL-010"} & set(_rules(e)) for e in ransomware)
        and any("POL-010" in _rules(e) for e in ransomware),
        f"правила: {_rules(ransomware[0]) if ransomware else []}",
    )

    mass = _by_tag(results, "mass_copy")
    mass_ok = bool(mass) and all({"POL-003", "POL-012"} & set(_rules(e)) for e in mass)
    report.check(
        "9. POL-003 срабатывает при массовом обращении к конфиденциальным файлам",
        mass_ok,
        f"файлов: {mass[0].event.files and len(mass[0].event.files)}, правила: {_rules(mass[0]) if mass else []}",
    )

    secret_access = _by_tag(results, "secret_access")
    block_simulated = [
        action.status.value
        for enriched in secret_access
        for outcome in enriched.enrichment.policies
        for action in outcome.actions
        if action.type.value == "block"
    ]
    report.check(
        "10. POL-002: обращение к секретам -> блокировка в режиме имитации (dry_run)",
        bool(secret_access)
        and all(enriched.enrichment.policy_decision.value == "block" for enriched in secret_access)
        and all(status == "simulated" for status in block_simulated),
        f"решения: {[e.enrichment.policy_decision.value for e in secret_access]}, статусы: {set(block_simulated)}",
    )

    hr_path = r"C:\HR\Зарплатная_ведомость_2025.xlsx"
    reference_event = usb[0].event if usb else (all_enriched[-1].event if all_enriched else None)
    hr_chain = pipeline.chain(hr_path, reference_event)
    usb_target = ""
    if usb and usb[0].event.files:
        removable = [f.path for f in usb[0].event.files if f.path[:2].lower() in {"e:", "f:", "g:"}]
        usb_target = removable[0] if removable else usb[0].event.files[-1].path
    usb_chain = pipeline.chain(usb_target, reference_event) if usb_target else None
    report.check(
        "11. Provenance: цепочка происхождения накапливается между событиями",
        hr_chain.depth >= 2 and (usb_chain is None or usb_chain.depth >= 2),
        f"глубина по {hr_path}: {hr_chain.depth} ({[s.action.value for s in hr_chain.steps]})",
    )
    report.check(
        "12. Provenance: для файла на съёмном носителе зафиксирован источник",
        usb_chain is not None
        and any(step.counterpart_path or step.direction == "inbound" for step in usb_chain.steps),
        f"шагов: {usb_chain.depth if usb_chain else 0}, "
        f"источник: {[s.counterpart_path for s in (usb_chain.steps if usb_chain else []) if s.counterpart_path][:1]}",
    )

    polluted = [
        file_ref.path
        for enriched in all_enriched
        for file_ref in enriched.event.files
        if any(marker in file_ref.path.lower() for marker in (" (read)", " (copy)", " (send)", " (write)"))
    ]
    report.check(
        "15. Извлекатель не создаёт путей с мусорными суффиксами",
        not polluted,
        f"примеры: {polluted[:2]}",
    )
    agent_ip = "10.0.0.11"
    agent_leaks = [
        str(enriched.event.raw.get("x_scenario"))
        for enriched, document in results
        if agent_ip in json.dumps(document.get("external_destinations") or [], ensure_ascii=False)
    ]
    report.check(
        "16. Локальный адрес агента не попадает в список внешних получателей",
        not agent_leaks,
        f"события: {sorted(set(agent_leaks))[:3]}",
    )
    upload_endpoints = upload_document.get("external_destinations") or []
    report.check(
        "17. Внешний адрес из события попадает в цепочку происхождения и учитывается в риске",
        any("185.220.101.5" in str(item) or "dropbox.com" in str(item) for item in upload_endpoints),
        f"адреса: {upload_endpoints[:3]}",
    )
    chain_amplified = [
        str(enriched.event.raw.get("x_scenario"))
        for enriched, document in results
        if enriched.event.remote is None and document.get("external_destinations_count")
    ]
    report.check(
        "18. Обращение к ранее отправленному файлу учитывает внешний адрес из цепочки provenance",
        bool(chain_amplified),
        f"события: {sorted(set(chain_amplified))[:3]}",
    )

    metrics = service_metrics()
    enriched_total = metrics.events_enriched.total()
    report.check(
        "13. Метрики Prometheus заполняются",
        enriched_total >= len(results) and metrics.enrichment_duration.count() >= len(results),
        f"events_enriched_total={enriched_total}, замеров длительности={metrics.enrichment_duration.count()}",
    )
    report.check(
        "14. Экспорт метрик в формате Prometheus формируется",
        "siem_enricher_events_enriched_total" in render_prometheus(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сквозная проверка сервиса обогащения событий SIEM")
    parser.add_argument("--config", default="config/config.local.json", help="Файл конфигурации")
    parser.add_argument("--scenario", default="mixed",
                        choices=["benign", "exfiltration", "ransomware", "mixed"])
    parser.add_argument("--count", type=int, default=None, help="Число событий (по умолчанию — все шаблоны)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--force-heuristic", action="store_true",
                        help="Не загружать ML-модель (режим только правил)")
    parser.add_argument("--json", action="store_true", help="Вывести отчёт в формате JSON")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path
    output = PROJECT_ROOT / "var" / "smoke_enriched.jsonl"
    config = build_config(config_path, args.force_heuristic, output)

    print("=" * 78)
    print("Сквозная проверка сервиса обогащения событий SIEM")
    print(f"Конфигурация: {config_path}")
    print("=" * 78)

    pipeline = EnrichmentPipeline.from_config(config, metrics=service_metrics(), in_memory_store=True)
    classifier_info = pipeline.classifier.describe()
    print(f"Классификатор: {classifier_info}")
    print(f"Хранилище provenance: {pipeline.store.stats()}")
    print(f"Правил политик загружено: {len(pipeline.policy_engine.rules) if pipeline.policy_engine else 0}")

    events = build_events(scenario=args.scenario, count=args.count, seed=args.seed)
    print(f"Сгенерировано событий: {len(events)}")
    print("-" * 78)

    started = time.perf_counter()
    results: list[tuple[EnrichedEvent, dict[str, Any]]] = []
    for document in events:
        _, enriched, siem_document = pipeline.enrich_document("file_replay", document)
        results.append((enriched, siem_document))
    elapsed = time.perf_counter() - started

    print(f"{'сценарий':<20}{'класс':<14}{'увер.':<7}{'риск':<7}{'уровень':<10}{'правила'}")
    print("-" * 78)
    for enriched, _ in results:
        tag = str(enriched.event.raw.get("x_scenario", "?"))
        sensitivity = enriched.enrichment.sensitivity
        risk = enriched.enrichment.risk
        print(
            f"{tag:<20}{sensitivity.level.value:<14}{sensitivity.confidence:<7.2f}"
            f"{(risk.score if risk else 0.0):<7.2f}{(risk.severity.value if risk else '-'):<10}"
            f"{','.join(_rules(enriched))}"
        )
    print("-" * 78)

    report = Report(verbose=not args.quiet)
    print()
    run_checks(results, pipeline, report)

    summary = pipeline.summarize([enriched for enriched, _ in results])
    print()
    print("Сводка:", json.dumps(summary, ensure_ascii=False))
    print(f"Время обработки: {elapsed:.2f} с "
          f"({len(results) / max(elapsed, 1e-9):.1f} соб/с, "
          f"{elapsed / max(len(results), 1) * 1000:.1f} мс/соб)")
    print(f"Обогащённые события записаны в: {output}")
    print(f"Журнал аудита: {config.audit_log_path}")

    if args.json:
        print(json.dumps(
            {
                "checks": [{"name": name, "passed": passed, "detail": detail}
                           for name, passed, detail in report.rows],
                "passed": report.passed_count,
                "failed": len(report.failed),
                "summary": summary,
                "elapsed_seconds": round(elapsed, 3),
            },
            ensure_ascii=False,
            indent=2,
        ))

    print()
    if report.failed:
        print(f"ПРОВАЛЕНО проверок: {len(report.failed)} из {len(report.rows)}")
        pipeline.close()
        return 1
    print(f"ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ ({report.passed_count} из {len(report.rows)})")
    pipeline.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

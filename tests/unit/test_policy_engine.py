"""Тесты движка применения политик: условия, действия, маскирование, блокировка."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from siem_enricher.audit import AuditLogger
from siem_enricher.config import ConfigError
from siem_enricher.metrics import service_metrics
from siem_enricher.models.enums import ActionStatus, PolicyDecision
from siem_enricher.policy import (
    DryRunBlocker,
    PolicyEngine,
    WebhookBlocker,
    build_blocker,
    load_rules,
    mask_value,
    parse_rule,
    validate_rules,
)

DOCUMENT: dict = {
    "event_id": "evt-1",
    "action": "upload",
    "data_sensitivity": "confidential",
    "sensitivity_confidence": 0.81,
    "risk_score": 0.83,
    "files_count": 1,
    "external_destinations_count": 1,
    "files": [{"path": r"C:\HR\Ведомость.xlsx", "extension": ".xlsx"}],
    "file": {"path": r"C:\HR\Ведомость.xlsx"},
    "user": {"name": "ivanov", "is_privileged": False},
    "raw_event": {"data": {"win": {"eventdata": {"targetFilename": r"C:\HR\Ведомость.xlsx"}}}},
    "tags": [],
}

RULES = {
    "version": "1.0",
    "rules": [
        {
            "id": "T-001",
            "title": "Отправка конфиденциального файла во внешний адрес",
            "priority": 100,
            "severity": "critical",
            "tags": ["dlp:exfiltration"],
            "when": {"all": [
                {"field": "data_sensitivity", "op": "gte", "value": "confidential"},
                {"field": "action", "op": "in", "value": ["upload", "send"]},
                {"field": "external_destinations_count", "op": "gte", "value": 1},
            ]},
            "then": [
                {"type": "alert", "channel": "siem", "severity": "critical"},
                {"type": "mask_field", "fields": ["files[*].path", "user.name"], "strategy": "hash"},
                {"type": "tag", "value": "dlp:exfiltration"},
            ],
        },
        {
            "id": "T-002",
            "title": "Обращение к кадровому каталогу",
            "priority": 50,
            "severity": "high",
            "when": {"all": [
                {"field": "files[*].path", "op": "regex", "value": r"(?i)\\hr\\"},
            ]},
            "then": [{"type": "alert", "channel": "siem", "severity": "high"}],
        },
    ],
}

BLOCK_RULES = {
    "version": "1.0",
    "rules": [
        {
            "id": "B-001",
            "title": "Обращение к объектам класса secret",
            "priority": 90,
            "severity": "critical",
            "when": {"all": [{"field": "data_sensitivity", "op": "eq", "value": "secret"}]},
            "then": [
                {"type": "alert", "channel": "siem", "severity": "critical"},
                {"type": "block", "target": "process", "reason": "проверка"},
            ],
        },
        {
            "id": "B-002",
            "title": "Правило низкого приоритета",
            "priority": 10,
            "severity": "low",
            "when": {"all": [{"field": "data_sensitivity", "op": "eq", "value": "secret"}]},
            "then": [{"type": "tag", "value": "lower-priority"}],
        },
    ],
}


class PolicyEngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.rules_path = self.tmp / "policies.json"
        self.audit_path = self.tmp / "audit.jsonl"
        self._dump(RULES)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _dump(self, payload: dict) -> None:
        self.rules_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def _engine(self, mode: str = "dry_run", **kwargs) -> PolicyEngine:
        return PolicyEngine.from_file(
            self.rules_path,
            mode=mode,
            audit_path=self.audit_path,
            metrics=service_metrics(),
            **kwargs,
        )

    # --- разбор правил ---
    def test_load_rules_sorted_by_priority(self) -> None:
        rules = load_rules(self.rules_path)
        self.assertEqual([rule.id for rule in rules], ["T-001", "T-002"])
        self.assertEqual(validate_rules(rules), [])

    def test_duplicate_rule_ids_rejected(self) -> None:
        self._dump({"rules": [RULES["rules"][0], RULES["rules"][0]]})
        with self.assertRaises(ConfigError):
            load_rules(self.rules_path)

    def test_unsupported_operator_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            parse_rule({"id": "X", "when": {"all": [{"field": "a", "op": "~=", "value": 1}]},
                        "then": [{"type": "tag", "value": "t"}]})

    def test_mask_action_requires_fields(self) -> None:
        with self.assertRaises(ConfigError):
            parse_rule({"id": "X", "when": {"all": [{"field": "a", "op": "exists"}]},
                        "then": [{"type": "mask_field"}]})

    def test_rule_without_condition_is_reported(self) -> None:
        rule = parse_rule({"id": "X", "then": [{"type": "tag", "value": "t"}]})
        self.assertTrue(any("пустое условие" in problem for problem in validate_rules([rule])))

    # --- применение ---
    def test_matching_rule_masks_and_tags(self) -> None:
        engine = self._engine()
        document = copy.deepcopy(DOCUMENT)
        evaluation = engine.evaluate(document)

        self.assertEqual([outcome.rule_id for outcome in evaluation.outcomes], ["T-001", "T-002"])
        self.assertEqual(evaluation.decision, PolicyDecision.MASK)
        self.assertIn("files[*].path", evaluation.masked_fields)
        self.assertTrue(document["files"][0]["path"].startswith("sha256:"))
        self.assertEqual(document["user"]["name"], mask_value("ivanov"))
        self.assertIn("dlp:exfiltration", document["tags"])

    def test_masking_is_applied_after_all_conditions(self) -> None:
        """Маскирование не должно ломать условия правил более низкого приоритета."""
        engine = self._engine()
        evaluation = engine.evaluate(copy.deepcopy(DOCUMENT))
        self.assertIn("T-002", evaluation.rule_ids)

    def test_audit_log_records_decisions(self) -> None:
        engine = self._engine()
        engine.evaluate(copy.deepcopy(DOCUMENT))
        records = AuditLogger(self.audit_path).read_all()
        kinds = {record["kind"] for record in records}
        self.assertIn("policy_decision", kinds)
        self.assertEqual({record["rule_id"] for record in records if record["kind"] == "policy_decision"},
                         {"T-001", "T-002"})

    def test_dry_run_does_not_change_document(self) -> None:
        engine = self._engine()
        document = copy.deepcopy(DOCUMENT)
        evaluation = engine.evaluate(document, apply_actions=False)
        self.assertEqual(document, DOCUMENT)
        self.assertTrue(evaluation.outcomes)
        self.assertTrue(all(not outcome.actions for outcome in evaluation.outcomes))

    def test_block_is_simulated_in_dry_run_and_stops_lower_priority_rules(self) -> None:
        self._dump(BLOCK_RULES)
        engine = self._engine(mode="dry_run")
        document = copy.deepcopy(DOCUMENT)
        document["data_sensitivity"] = "secret"
        evaluation = engine.evaluate(document)

        self.assertEqual(evaluation.decision, PolicyDecision.BLOCK)
        self.assertEqual([outcome.rule_id for outcome in evaluation.outcomes], ["B-001"])
        self.assertIn("B-002", evaluation.skipped_rules)

        block_actions = [
            action for outcome in evaluation.outcomes for action in outcome.actions
            if action.type.value == "block"
        ]
        self.assertEqual(len(block_actions), 1)
        self.assertEqual(block_actions[0].status, ActionStatus.SIMULATED)
        self.assertIn("dry_run", block_actions[0].detail)

    def test_non_matching_rules_do_not_trigger(self) -> None:
        engine = self._engine()
        document = copy.deepcopy(DOCUMENT)
        document["action"] = "read"
        document["data_sensitivity"] = "public"
        evaluation = engine.evaluate(document)
        self.assertEqual(evaluation.rule_ids, ["T-002"])  # сработал только каталог
        self.assertEqual(evaluation.decision, PolicyDecision.ALERT)

    def test_reload_rules(self) -> None:
        engine = self._engine()
        self.assertEqual(len(engine.rules), 2)
        self._dump({"rules": [RULES["rules"][0]]})
        self.assertEqual(engine.reload(), 1)

    # --- маскирование и блокировка ---
    def test_mask_strategies(self) -> None:
        self.assertEqual(mask_value("secret", "redact"), "***")
        self.assertTrue(mask_value("C:\\HR\\file.xlsx", "hash").startswith("sha256:"))
        self.assertTrue(mask_value("ivanov", "partial").startswith("iva"))
        token = mask_value("ivanov", "tokenize", "key-1")
        self.assertEqual(token, mask_value("ivanov", "tokenize", "key-1"))
        self.assertNotEqual(token, mask_value("ivanov", "tokenize", "key-2"))

    def test_blocker_selection(self) -> None:
        self.assertIsInstance(build_blocker("dry_run"), DryRunBlocker)
        self.assertIsInstance(build_blocker("live"), DryRunBlocker)  # нечем блокировать -> имитация
        blocker = build_blocker("live", webhook_url="https://soar.example/api/block")
        self.assertIsInstance(blocker, WebhookBlocker)

    def test_rule_summary_contains_human_readable_conditions(self) -> None:
        summary = self._engine().rules_summary()
        self.assertEqual(summary[0]["id"], "T-001")
        self.assertIn("data_sensitivity", summary[0]["when"])
        self.assertEqual(summary[0]["decision"], "mask")


if __name__ == "__main__":
    unittest.main()

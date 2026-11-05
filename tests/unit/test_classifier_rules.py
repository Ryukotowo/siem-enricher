"""Тесты эвристического классификатора конфиденциальности (правила по имени и каталогу)."""

from __future__ import annotations

import unittest

from siem_enricher.ml import HeuristicSensitivityClassifier
from siem_enricher.ml.hybrid import HybridSensitivityClassifier
from siem_enricher.models.enums import SensitivityLevel


class HeuristicClassifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = HeuristicSensitivityClassifier()

    def test_credentials_are_secret(self) -> None:
        for path in (
            r"C:\keys\id_rsa",
            r"C:\secrets\.env",
            r"C:\backup\Ключи_подписи.pem",
            r"C:\secrets\Пароли_от_сервисов.kdbx",
        ):
            with self.subTest(path=path):
                assessment = self.classifier.predict(path)
                self.assertEqual(assessment.level, SensitivityLevel.SECRET)
                self.assertGreater(assessment.confidence, 0.5)
                self.assertTrue(
                    any(key.startswith("policy:") and value > 0 for key, value in assessment.scores.items()),
                    "для криптоматериалов должен формироваться признак размещения",
                )

    def test_public_share_and_templates_are_public(self) -> None:
        for path in (r"C:\Public\readme.md", r"C:\Public\Шаблон_письма_клиенту.docx"):
            with self.subTest(path=path):
                assessment = self.classifier.predict(path)
                self.assertEqual(assessment.level, SensitivityLevel.PUBLIC)
                signal = HybridSensitivityClassifier.policy_signal(assessment)
                self.assertIsNotNone(signal)
                self.assertEqual(signal[0], SensitivityLevel.PUBLIC)

    def test_personal_and_financial_documents_are_confidential(self) -> None:
        for path in (
            r"C:\HR\Зарплатная_ведомость_2025.xlsx",
            r"C:\HR\Паспортные_данные_сотрудников.xlsx",
            r"\\srv-file-01\HR\Приказы_о_приеме_на_работу.docx",
            r"C:\Бухгалтерия\Счет_фактура_№1420.docx",
            r"C:\Клиенты\База_клиентов_CRM_export.csv",
        ):
            with self.subTest(path=path):
                assessment = self.classifier.predict(path)
                self.assertEqual(assessment.level, SensitivityLevel.CONFIDENTIAL)
                self.assertGreaterEqual(assessment.level.rank, SensitivityLevel.CONFIDENTIAL.rank)

    def test_internal_documents(self) -> None:
        # Проектный каталог трактуется как интеллектуальная собственность (confidential),
        # служебным остаётся только каталог общих документов.
        self.assertEqual(
            self.classifier.predict(r"C:\Projects\Отчет_о_работе_2025.docx").level,
            SensitivityLevel.CONFIDENTIAL,
        )
        for path in (r"C:\Общие\Регламент_информационной_безопасности.pdf",):
            with self.subTest(path=path):
                self.assertEqual(self.classifier.predict(path).level, SensitivityLevel.INTERNAL)

    def test_default_class_when_no_rules_match(self) -> None:
        assessment = self.classifier.predict(r"X:\data\файл.bin")
        self.assertEqual(assessment.level, SensitivityLevel.INTERNAL)
        self.assertEqual(assessment.method, "default")
        self.assertLess(assessment.confidence, 0.5)

    def test_scores_include_policy_markers_only_when_present(self) -> None:
        """Признаки размещения появляются только при срабатывании правил каталога/пометок."""
        inside = self.classifier.predict(r"C:\Projects\Отчет_о_работе_2025.docx")
        self.assertIn("policy:confidential", inside.scores)  # каталог проектов = интеллектуальная собственность
        outside = self.classifier.predict(r"X:\data\файл.bin")
        self.assertEqual([key for key in outside.scores if key.startswith("policy:")], [])

    def test_predict_many_is_consistent_with_predict(self) -> None:
        paths = [r"C:\HR\Зарплатная_ведомость_2025.xlsx", r"C:\Public\readme.md"]
        batch = self.classifier.predict_many(paths)
        single = [self.classifier.predict(path) for path in paths]
        self.assertEqual([a.level for a in batch], [a.level for a in single])

    def test_describe_reports_method_and_version(self) -> None:
        info = self.classifier.describe()
        self.assertEqual(info["method"], "heuristic")
        self.assertTrue(info["model_version"])


if __name__ == "__main__":
    unittest.main()

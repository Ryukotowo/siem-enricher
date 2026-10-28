"""Тесты извлечения метаданных из событий SIEM."""

from __future__ import annotations

import unittest

from siem_enricher.config import ExtractorConfig
from siem_enricher.extractor import MetadataExtractor
from siem_enricher.models.enums import ProvenanceAction

WAZUH_EVENT = {
    "@timestamp": "2025-03-03T09:12:00Z",
    "id": "1700000000.000001",
    "agent": {"id": "001", "name": "pc-hr-01", "ip": "10.0.0.11"},
    "manager": {"name": "wazuh-manager"},
    "rule": {"id": "92300", "level": 10, "description": "Копирование файла на съёмный носитель"},
    "location": "EventChannel",
    "data": {
        "action": "copy",
        "win": {
            "system": {"computer": "pc-hr-01", "eventID": "11"},
            "eventdata": {
                "targetFilename": r"E:\Копия_Ведомость_2025.xlsx",
                "sourceFilename": r"C:\HR\Ведомость_2025.xlsx",
                "image": r"C:\Windows\explorer.exe",
                "user": r"DOMAIN\ivanov",
                "destinationIp": "185.220.101.5",
            },
        },
    },
    "full_log": r"Копирование файла: C:\HR\Ведомость_2025.xlsx (copy)",
}


class MetadataExtractorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = MetadataExtractor(ExtractorConfig(drop_system_paths=False))

    def test_normalize_wazuh_alert(self) -> None:
        event = self.extractor.normalize("wazuh_indexer", WAZUH_EVENT)

        self.assertEqual(event.source, "wazuh_indexer")
        self.assertEqual(event.event_id, "1700000000.000001")
        self.assertEqual(event.action, ProvenanceAction.COPY)
        self.assertEqual(event.host, "pc-hr-01")

        # Пользователь и процесс
        self.assertIsNotNone(event.user)
        self.assertEqual(event.user.name, "ivanov")
        self.assertEqual(event.user.domain, "DOMAIN")
        self.assertFalse(event.user.is_privileged)

        self.assertIsNotNone(event.process)
        self.assertEqual(event.process.name, "explorer.exe")
        self.assertEqual(event.process.path, r"C:\Windows\explorer.exe")

        # Внешний адрес получателя данных
        self.assertIsNotNone(event.remote)
        self.assertEqual(event.remote.ip, "185.220.101.5")
        self.assertTrue(event.remote.is_external)

        # Правило SIEM
        self.assertIsNotNone(event.rule)
        self.assertEqual(event.rule.id, "92300")
        self.assertEqual(event.rule.level, 10)

    def test_files_and_actions(self) -> None:
        event = self.extractor.normalize("wazuh_indexer", WAZUH_EVENT)
        paths = {file_ref.path: file_ref.action for file_ref in event.files}

        self.assertIn(r"C:\HR\Ведомость_2025.xlsx", paths)
        self.assertIn(r"E:\Копия_Ведомость_2025.xlsx", paths)
        # Файл-источник остаётся «читаемым», целевой получает действие события
        self.assertEqual(paths[r"C:\HR\Ведомость_2025.xlsx"], ProvenanceAction.READ)
        self.assertEqual(paths[r"E:\Копия_Ведомость_2025.xlsx"], ProvenanceAction.COPY)

    def test_no_garbage_suffix_from_full_log(self) -> None:
        event = self.extractor.normalize("wazuh_indexer", WAZUH_EVENT)
        for file_ref in event.files:
            self.assertNotIn("(copy)", file_ref.path.lower())
            self.assertNotIn("(read)", file_ref.path.lower())

    def test_agent_address_is_not_remote_endpoint(self) -> None:
        """Адрес агента (agent.ip) не должен становиться получателем данных."""
        document = {
            "@timestamp": "2025-03-03T09:12:00Z",
            "agent": {"name": "pc-1", "ip": "10.0.0.11"},
            "data": {"win": {"eventdata": {"targetFilename": r"C:\Public\readme.md"}}},
        }
        event = self.extractor.normalize("wazuh_indexer", document)
        self.assertIsNone(event.remote)
        self.assertEqual(event.host, "pc-1")

    def test_system_paths_can_be_dropped(self) -> None:
        extractor = MetadataExtractor(ExtractorConfig(drop_system_paths=True))
        document = {
            "@timestamp": "2025-03-03T09:12:00Z",
            "data": {"win": {"eventdata": {
                "targetFilename": r"C:\Windows\System32\drivers\etc\hosts",
                "sourceFilename": r"C:\HR\Ведомость_2025.xlsx",
            }}},
        }
        event = extractor.normalize("test", document)
        self.assertEqual([f.path for f in event.files], [r"C:\HR\Ведомость_2025.xlsx"])

    def test_embedded_paths_are_extracted_from_command_line(self) -> None:
        document = {
            "@timestamp": "2025-03-03T09:12:00Z",
            "data": {"win": {"eventdata": {
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "commandLine": r'powershell -Command "Copy-Item C:\HR\Ведомость_2025.xlsx E:\leak.xlsx"',
            }}},
        }
        event = self.extractor.normalize("test", document)
        self.assertTrue(any(f.is_embedded for f in event.files))
        self.assertIn(r"E:\leak.xlsx", [f.path for f in event.files])

    def test_ecs_style_document(self) -> None:
        document = {
            "@timestamp": "2025-03-03T09:12:00Z",
            "event": {"action": "read", "id": "abc-1"},
            "host": {"name": "srv-01"},
            "user": {"name": "petrova"},
            "file": {"path": r"\\srv-file-01\обмен\Общий_отчет.xlsx"},
            "process": {"name": "excel.exe"},
        }
        event = self.extractor.normalize("elasticsearch", document)
        self.assertEqual(event.action, ProvenanceAction.READ)
        self.assertEqual(event.user.name, "petrova")
        self.assertEqual(event.host, "srv-01")
        self.assertEqual([f.path for f in event.files], [r"\\srv-file-01\обмен\Общий_отчет.xlsx"])


if __name__ == "__main__":
    unittest.main()

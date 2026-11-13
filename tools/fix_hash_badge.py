"""Значок «имя скрыто» показывается и когда имя неизвестно, но есть отпечаток."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "src" / "siem_enricher" / "service" / "panel.py"
TEST = ROOT / "tests" / "unit" / "test_panel.py"

OLD = '''def _hash_only(file_info: dict[str, Any]) -> bool:
    """Имя файла пришло хэшем — объект известен только по отпечатку."""
    name = str(file_info.get("name") or "").strip().lower()
    path = str(file_info.get("path") or "").strip().lower()
    return name.startswith("sha256:") or (not name and path.startswith("sha256:"))'''

NEW = '''def _hash_only(file_info: dict[str, Any]) -> bool:
    """Имя файла неизвестно — объект известен только по отпечатку."""
    name = str(file_info.get("name") or "").strip().lower()
    path = str(file_info.get("path") or "").strip().lower()
    if name.startswith("sha256:") or (not name and path.startswith("sha256:")):
        return True
    hashes = file_info.get("hashes") or {}
    return bool(hashes) and not name and not path'''

TEST_OLD = '''    def test_hash_only_file_is_marked(self) -> None:'''
TEST_NEW = '''    def test_hash_without_name_is_marked(self) -> None:
        document = {
            "@timestamp": "2026-11-13T10:00:00Z", "event_id": "e-hash2",
            "action": "read", "files": [{"hashes": {"sha256": "abc"}, "path": "", "name": ""}],
            "data_sensitivity": "internal", "risk_score": 0.2,
        }
        record = panel_module.event_to_panel(document)
        self.assertTrue(record["hash_only"])
        self.assertEqual(record["file"], "(название скрыто)")

    def test_hash_only_file_is_marked(self) -> None:'''


def main() -> int:
    changed = 0
    text = PANEL.read_text(encoding="utf-8")
    if NEW not in text:
        if OLD not in text:
            print("!! не найдена функция _hash_only")
            return 1
        text = text.replace(OLD, NEW, 1)
        PANEL.write_text(text, encoding="utf-8")
        ast.parse(text)
        changed += 1
        print("panel: учитываются hashes без имени и пути")

    test_text = TEST.read_text(encoding="utf-8")
    if "test_hash_without_name_is_marked" not in test_text:
        if TEST_OLD not in test_text:
            print("  предупреждение: не найден тестовый класс")
        else:
            test_text = test_text.replace(TEST_OLD, TEST_NEW, 1)
            TEST.write_text(test_text, encoding="utf-8")
            ast.parse(test_text)
            changed += 1
            print("тест: случай hashes без имени")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

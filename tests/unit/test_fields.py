"""Тесты доступа к полям документа по путям вида ``files[*].path``."""

from __future__ import annotations

import unittest

from siem_enricher.policy.fields import (
    collect_missing,
    flatten,
    get_first,
    get_values,
    has_path,
    iter_targets,
    parse_path,
    set_values,
)


class DocumentFieldsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.document = {
            "event_id": "evt-1",
            "action": "upload",
            "files": [
                {"path": r"C:\HR\Ведомость.xlsx", "extension": ".xlsx"},
                {"path": r"E:\Копия.xlsx", "extension": ".xlsx"},
            ],
            "user": {"name": "ivanov", "is_privileged": False},
            "nested": {"deep": {"value": 5}},
            "tags": [],
        }

    def test_parse_path(self) -> None:
        self.assertEqual(parse_path("files[*].path"), ["files", "*", "path"])
        self.assertEqual(parse_path("user.name"), ["user", "name"])
        self.assertEqual(parse_path("files[0].path"), ["files", "0", "path"])
        self.assertEqual(parse_path(""), [])

    def test_get_values_with_wildcard(self) -> None:
        self.assertEqual(
            get_values(self.document, "files[*].path"),
            [r"C:\HR\Ведомость.xlsx", r"E:\Копия.xlsx"],
        )
        self.assertEqual(get_values(self.document, "user.name"), ["ivanov"])
        self.assertEqual(get_values(self.document, "user.is_privileged"), [False])

    def test_missing_paths(self) -> None:
        self.assertEqual(get_values(self.document, "user.surname"), [])
        self.assertEqual(get_values(self.document, "nope.deep.value"), [])
        self.assertIsNone(get_first(self.document, "missing"))
        self.assertEqual(get_first(self.document, "missing", "fallback"), "fallback")
        self.assertFalse(has_path(self.document, "missing"))
        self.assertTrue(has_path(self.document, "user.name"))

    def test_wildcard_over_mapping(self) -> None:
        document = {"scores": {"a": 1, "b": 2}}
        self.assertEqual(sorted(get_values(document, "scores[*]")), [1, 2])

    def test_set_values_with_transform(self) -> None:
        changed = set_values(self.document, "files[*].path", transform=lambda value: f"masked:{value}")
        self.assertEqual(len(changed), 2)
        self.assertEqual(
            [item["path"] for item in self.document["files"]],
            [r"masked:C:\HR\Ведомость.xlsx", r"masked:E:\Копия.xlsx"],
        )

    def test_set_values_on_plain_field(self) -> None:
        changed = set_values(self.document, "action", "upload-masked")
        self.assertEqual(changed, ["action"])
        self.assertEqual(self.document["action"], "upload-masked")

    def test_iter_targets_reports_containers(self) -> None:
        targets = list(iter_targets(self.document, "files[*].extension"))
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].value, ".xlsx")

    def test_flatten(self) -> None:
        flat = flatten(self.document)
        self.assertIn("user.name", flat)
        self.assertIn("files[0].path", flat)
        self.assertEqual(flat["nested.deep.value"], 5)

    def test_collect_missing(self) -> None:
        self.assertEqual(
            collect_missing(self.document, ["user.name", "user.surname"]),
            ["user.surname"],
        )


if __name__ == "__main__":
    unittest.main()

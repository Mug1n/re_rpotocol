from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


PREPARE = load("prepare", ROOT / "experiments/M11/prepare_rows.py")
M11 = load("m11", ROOT / "experiments/M11/run.py")


def rows_file(rows, feature_definition_version="0.1"):
    return {"schema_version": "0.1",
            "feature_definition_version": feature_definition_version,
            "rows": rows}


def labels_file(assignments):
    return {"schema_version": "0.1", "assignments": assignments}


class PrepareTests(unittest.TestCase):
    def _run(self, rows, assignments):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rp = root / "rows.json"
            lp = root / "labels.json"
            op = root / "prepared.json"
            rp.write_text(json.dumps(rows_file(rows)), encoding="utf-8")
            lp.write_text(json.dumps(labels_file(assignments)), encoding="utf-8")
            result = PREPARE.prepare(rp, lp, op)
            return result

    def test_labels_group_and_split_are_attached_only_where_assigned(self):
        rows = [
            {"id": "a", "group_id": None, "labels": {}, "features": {"x": 1}},
            {"id": "b", "group_id": None, "labels": {}, "features": {"x": 2}},
        ]
        result = self._run(rows, [
            {"id": "a", "labels": {"application": "upload"}, "group_id": "g1", "split": "train"},
        ])
        by_id = {row["id"]: row for row in result["rows"]}
        self.assertEqual("upload", by_id["a"]["labels"]["application"])
        self.assertEqual("g1", by_id["a"]["group_id"])
        self.assertEqual("train", by_id["a"]["split"])
        self.assertEqual({}, by_id["b"]["labels"])
        self.assertIsNone(by_id["b"]["group_id"])

    def test_prepared_rows_train_via_run(self):
        rows = [
            {"id": str(i), "group_id": None, "labels": {},
             "features": {"x": 100 if i % 2 else 1}}
            for i in range(12)
        ]
        assignments = [
            {"id": str(i), "labels": {"application": "a" if i % 2 else "b"},
             "group_id": f"g{i}"}
            for i in range(12)
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rp = root / "rows.json"
            lp = root / "labels.json"
            rp.write_text(json.dumps(rows_file(rows)), encoding="utf-8")
            lp.write_text(json.dumps(labels_file(assignments)), encoding="utf-8")
            prepared = root / "prepared.json"
            PREPARE.prepare(rp, lp, prepared)
            result = M11.analyze(prepared, root / "out", task="application")
            self.assertEqual("ok", result["status"])
            self.assertEqual("grouped_cv", result["parameters"]["split_strategy"])

    def test_duplicate_and_phantom_assignments_are_rejected(self):
        rows = [{"id": "a", "group_id": None, "labels": {}, "features": {"x": 1}}]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._run(rows, [
                {"id": "a", "labels": {"application": "u"}, "group_id": "g1"},
                {"id": "a", "labels": {"application": "u"}, "group_id": "g2"},
            ])
        with self.assertRaisesRegex(ValueError, "not present"):
            self._run(rows, [{"id": "missing", "labels": {"application": "u"}, "group_id": "g1"}])

    def test_assignment_missing_group_or_invalid_split_is_rejected(self):
        rows = [{"id": "a", "group_id": None, "labels": {}, "features": {"x": 1}}]
        with self.assertRaisesRegex(ValueError, "group_id"):
            self._run(rows, [{"id": "a", "labels": {"application": "u"}, "group_id": ""}])
        with self.assertRaisesRegex(ValueError, "split"):
            self._run(rows, [{"id": "a", "labels": {"application": "u"}, "group_id": "g1", "split": "bogus"}])


if __name__ == "__main__":
    unittest.main()

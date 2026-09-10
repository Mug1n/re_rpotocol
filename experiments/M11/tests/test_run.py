from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
import tempfile
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


M11 = load("m11", ROOT / "experiments/M11/run.py")
SCHEMA = json.loads(
    (ROOT / "research/M11-behavior-classification/classification.schema.json")
    .read_text(encoding="utf-8")
)


def dataset(rows):
    return {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": rows}


def training_rows():
    rows = []
    for index in range(12):
        label = "alpha" if index % 2 else "beta"
        rows.append({
            "id": str(index), "group_id": f"g{index}",
            "labels": {"application": label},
            "features": {
                "bytes": 100 if label == "alpha" else 1,
                "packets": 10 if label == "alpha" else 1,
            },
        })
    return rows


class M11Tests(unittest.TestCase):
    def analyze_fixture(self, rows, *, task="application"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rows.json"
            source.write_text(json.dumps(dataset(rows)), encoding="utf-8")
            return M11.analyze(source, root / "out", task=task)

    def test_absent_labels_are_not_scored(self):
        result = self.analyze_fixture([
            {"id": "a", "group_id": "g", "features": {"bytes": 1}}
        ])
        self.assertEqual("insufficient_labels", result["status"])
        self.assertIsNone(result["metrics"])

    def test_single_class_is_not_scored(self):
        result = self.analyze_fixture([
            {"id": "a", "group_id": "g1", "labels": {"application": "x"}, "features": {"bytes": 1}},
            {"id": "b", "group_id": "g2", "labels": {"application": "x"}, "features": {"bytes": 2}},
        ])
        self.assertEqual("insufficient_labels", result["status"])
        self.assertIsNone(result["model"])

    def test_empty_is_explicit(self):
        self.assertEqual("empty", self.analyze_fixture([])["status"])

    def test_training_is_grouped_and_publishes_verifiable_model(self):
        rows = training_rows()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rows.json"
            source.write_text(json.dumps(dataset(rows)), encoding="utf-8")
            output = root / "out"
            result = M11.analyze(source, output, task="application")
            self.assertEqual("ok", result["status"])
            self.assertFalse(set(result["split"]["train_groups"]) & set(result["split"]["test_groups"]))
            model_path = output / "model.joblib"
            self.assertTrue(model_path.is_file())
            artifact = result["model"]["artifact"]
            self.assertEqual(model_path.stat().st_size, artifact["length"])
            self.assertEqual(hashlib.sha256(model_path.read_bytes()).hexdigest(), artifact["sha256"])

    def test_impossible_stratified_group_split_is_not_scored(self):
        rows = [
            {"id": "a", "group_id": "ga", "labels": {"application": "alpha"}, "features": {"bytes": 1}},
            {"id": "b", "group_id": "gb", "labels": {"application": "beta"}, "features": {"bytes": 2}},
        ]
        result = self.analyze_fixture(rows)
        self.assertEqual("insufficient_labels", result["status"])
        self.assertIsNone(result["model"])
        self.assertTrue(any("preserved every class" in item for item in result["warnings"]))

    def test_cluster_id_is_forbidden_as_behavior_label(self):
        with self.assertRaisesRegex(ValueError, "cluster_id"):
            self.analyze_fixture(training_rows(), task="cluster_id")

    def test_invalid_numeric_and_inconsistent_rows_are_rejected(self):
        invalid_sets = [
            [{"id": "a", "features": {"x": math.nan}}],
            [{"id": "a", "features": {"x": math.inf}}],
            [{"id": "a", "features": {"x": True}}],
            [{"id": "a", "features": {"x": 1}}, {"id": "b", "features": {"y": 2}}],
            [{"id": "a", "features": {"x": 1}}, {"id": "a", "features": {"x": 2}}],
        ]
        for rows in invalid_sets:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.analyze_fixture(rows)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rows.json"
            source.write_text(json.dumps(dataset([])), encoding="utf-8")
            output = root / "out"
            output.mkdir()
            marker = output / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                M11.analyze(source, output, task="application")
            self.assertEqual("keep", marker.read_text(encoding="utf-8"))

    def test_result_schema_is_strict(self):
        result = self.analyze_fixture([])
        jsonschema.validate(result, SCHEMA)
        invalid = copy.deepcopy(result)
        invalid["unexpected"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, SCHEMA)


if __name__ == "__main__":
    unittest.main()

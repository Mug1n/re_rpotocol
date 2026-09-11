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


M11 = load("m11", ROOT / "experiments/M11/run.py")
EVALUATE = load("evaluate", ROOT / "experiments/M11/evaluate.py")


def rows_file(rows):
    return {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": rows}


def _train(root):
    training = [
        {"id": f"t{i}", "group_id": f"g{i}",
         "labels": {"application": "alpha" if i % 2 else "beta"},
         "features": {"x": 100 if i % 2 else 1}}
        for i in range(12)
    ]
    source = root / "training.json"
    source.write_text(json.dumps(rows_file(training)), encoding="utf-8")
    classification = root / "classification"
    M11.analyze(source, classification, task="application")
    return classification / "classification.json"


class EvaluateTests(unittest.TestCase):
    def test_held_out_separable_rows_score_perfectly_without_retraining(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            classification = _train(root)
            held = root / "held.json"
            held.write_text(json.dumps(rows_file([
                {"id": "h0", "group_id": "hg0", "labels": {"application": "alpha"}, "features": {"x": 100}},
                {"id": "h1", "group_id": "hg1", "labels": {"application": "beta"}, "features": {"x": 1}},
            ])), encoding="utf-8")
            out = root / "eval.json"
            result = EVALUATE.evaluate(classification, held, out, task="application")
            self.assertEqual("evaluation_only", result["status"])
            self.assertEqual(1.0, result["metrics"]["macro_f1"])
            self.assertEqual(0.0, result["metrics"]["rejection_rate"])
            self.assertEqual(0, result["metrics"]["out_of_distribution_count"])

    def test_open_set_labels_are_counted_not_scored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            classification = _train(root)
            held = root / "held.json"
            held.write_text(json.dumps(rows_file([
                {"id": "o0", "group_id": "og0", "labels": {"application": "gamma"}, "features": {"x": 50}},
            ])), encoding="utf-8")
            out = root / "eval.json"
            result = EVALUATE.evaluate(classification, held, out, task="application")
            self.assertEqual(1, result["metrics"]["out_of_distribution_count"])
            self.assertNotIn("gamma", result["task"]["classes"])
            self.assertEqual(["alpha", "beta"], result["task"]["classes"])

    def test_model_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            classification = root / "classification.json"
            classification.write_text(json.dumps({
                "task": {"feature_schema_version": "0.1"},
                "model": {"artifact": {"artifact_ref": "missing.joblib", "sha256": "0" * 64},
                          "feature_names": ["x"]},
            }), encoding="utf-8")
            rows = root / "rows.json"
            rows.write_text(json.dumps(rows_file([{"id": "a", "labels": {"application": "x"}, "features": {"x": 1}}])),
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                EVALUATE.evaluate(classification, rows, root / "out.json", task="application")


if __name__ == "__main__":
    unittest.main()

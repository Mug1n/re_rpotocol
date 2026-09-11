from __future__ import annotations
import importlib.util, json, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


M11 = load("m11", ROOT / "experiments/M11/run.py")
BUILD = load("build", ROOT / "experiments/M11/build_rows.py")
PREDICT = load("predict", ROOT / "experiments/M11/predict.py")


def complete_m09_flow():
    return {"schema_version": "0.1", "flows": [{
        "flow_id": "flow", "packet_count": 3, "byte_count": 12,
        "packet_length": {"mean": 4, "p95": 4, "median": 4},
        "directional": {"node0_to_node1": {"packet_count": 2}},
        "node0_to_node1_byte_ratio": 0.5, "direction_switches": 1,
        "duration_seconds": 2,
        "packet_interarrival_seconds": {"mean": 1, "p95": 1},
        "interarrival_cv": 0.2,
        "burst": {"count": 1, "max_packets": 3},
        "integrity": {"retransmission_packets": 0, "gap_or_loss_packets": 0},
    }]}


class PredictTests(unittest.TestCase):
    def test_build_rows_keeps_labels_out_and_predicts_without_labels(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            m09 = root / "m09.json"
            m09.write_text(json.dumps(complete_m09_flow()), encoding="utf-8")
            rows_path = root / "rows.json"
            rows = BUILD.build(m09, rows_path)
            self.assertEqual({}, rows["rows"][0]["labels"])
            training = []
            for index in range(12):
                training.append({"id": str(index), "group_id": f"g{index}",
                                 "labels": {"task": "a" if index % 2 else "b"},
                                 "features": {"x": 100 if index % 2 else 1}})
            source = root / "training.json"
            source.write_text(json.dumps({"schema_version": "0.1",
                                          "feature_definition_version": "0.1",
                                          "rows": training}), encoding="utf-8")
            classification = root / "classification"
            M11.analyze(source, classification, task="task")
            inference = root / "inference.json"
            inference.write_text(json.dumps({"schema_version": "0.1",
                                             "feature_definition_version": "0.1",
                                             "rows": [{"id": "new", "group_id": None,
                                                       "labels": {}, "features": {"x": 100}}]}),
                                 encoding="utf-8")
            output = root / "prediction.json"
            result = PREDICT.predict(classification / "classification.json", inference, output)
            self.assertEqual("new", result["predictions"][0]["scope_id"])

    def test_low_confidence_prediction_is_rejected_as_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            training = [
                {"id": str(i), "group_id": f"g{i}",
                 "labels": {"task": "a" if i % 2 else "b"},
                 "features": {"x": 1.0}}
                for i in range(12)
            ]
            source = root / "training.json"
            source.write_text(json.dumps({"schema_version": "0.1",
                                          "feature_definition_version": "0.1",
                                          "rows": training}), encoding="utf-8")
            classification = root / "classification"
            M11.analyze(source, classification, task="task")
            classification_json = classification / "classification.json"
            payload = json.loads(classification_json.read_text(encoding="utf-8"))
            payload["parameters"]["reject_threshold"] = 0.9
            classification_json.write_text(json.dumps(payload), encoding="utf-8")
            inference = root / "inference.json"
            inference.write_text(json.dumps({"schema_version": "0.1",
                                             "feature_definition_version": "0.1",
                                             "rows": [{"id": "new", "group_id": None,
                                                       "labels": {}, "features": {"x": 1.0}}]}),
                                 encoding="utf-8")
            output = root / "prediction.json"
            result = PREDICT.predict(classification_json, inference, output)
            prediction = result["predictions"][0]
            self.assertTrue(prediction["rejected"])
            self.assertEqual("unknown", prediction["predicted_label"])

    def test_model_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p = root / "classification.json"
            p.write_text(json.dumps({"task": {"feature_schema_version": "0.1"},
                                     "model": {"artifact": {"artifact_ref": "missing.joblib",
                                                            "sha256": "0" * 64},
                                               "feature_names": ["x"]}}), encoding="utf-8")
            rows = root / "rows.json"
            rows.write_text(json.dumps({"feature_definition_version": "0.1", "rows": []}),
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                PREDICT.predict(p, rows, root / "out.json")


if __name__ == "__main__":
    unittest.main()

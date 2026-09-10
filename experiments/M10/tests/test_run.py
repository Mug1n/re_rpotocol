from __future__ import annotations

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


M10 = load("m10", ROOT / "experiments" / "M10" / "run.py")


def empty_summary(count=0, maximum=None, mean=None):
    return {"count": count, "min": mean, "max": maximum, "mean": mean,
            "median": mean, "p95": maximum, "sum": 0.0 if mean is None else mean * count}


def features(m01_path: Path, missing: bool = False) -> dict:
    length = empty_summary(4, 40.0, 25.0)
    direction = lambda count, size: {"packet_count": count, "bytes": size, "length": length}
    return {
        "schema_version": "0.1",
        "source": {"module": "M01", "artifact_path": str(m01_path),
                   "artifact_sha256": hashlib.sha256(m01_path.read_bytes()).hexdigest(),
                   "record_count": 1, "schema_version": "0.1"},
        "status": "partial" if missing else "ok",
        "parameters": {"retransmission_policy": "include", "burst_gap_seconds": 1.0,
                       "length_basis": "captured_length", "direction_role_mapping": "node_relative",
                       "quantile_method": "nearest_rank"},
        "feature_definition": {"version": "0.1", "time_unit": "seconds",
                               "byte_range": "captured packet length", "direction": "node_relative"},
        "metrics": {"flow_count": 1, "packet_count": 4},
        "flows": [{
            "flow_id": "f", "packet_ids": ["p0", "p1", "p2", "p3"],
            "packet_count": 4, "byte_count": 100,
            "directional": {"node0_to_node1": direction(3, 90),
                            "node1_to_node0": direction(1, 10)},
            "packet_length": length, "duration_seconds": None if missing else 80.0,
            "packet_interarrival_seconds": empty_summary(3, 12.0, 1.0),
            "interarrival_cv": 0.05, "rate_bytes_per_second": None if missing else 1.25,
            "direction_switches": 2, "node0_to_node1_byte_ratio": 0.9,
            "burst": {"gap_seconds": 1.0, "count": 1, "max_packets": 4},
            "integrity": {"truncated_packets": 0, "retransmission_packets": 0,
                          "out_of_order_packets": 0, "gap_or_loss_packets": 0},
        }],
        "unavailable_features": ([{"flow_id": "f", "feature": "duration_iat_rate_burst",
                                   "reason_code": "timestamp_missing_or_invalid"}]
                                 if missing else []),
        "warnings": [],
    }


class M10Tests(unittest.TestCase):
    def analyze_fixture(self, missing=False, mutate_upstream=False, **parameters):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "m01.json"
            upstream.write_text("upstream evidence", encoding="utf-8")
            value = features(upstream, missing)
            source = root / "m09.json"
            source.write_text(json.dumps(value), encoding="utf-8")
            if mutate_upstream:
                upstream.write_text("tampered", encoding="utf-8")
            output = root / "out"
            result = M10.analyze(source, output, **parameters)
            return result

    def test_rules_are_nonexclusive(self):
        result = self.analyze_fixture()
        self.assertEqual(
            {"direction_dominance", "periodicity_candidate", "bursty_transfer",
             "long_lived_intermittent"},
            {item["type"] for item in result["observations"]},
        )

    def test_missing_time_keeps_only_non_temporal_rule(self):
        result = self.analyze_fixture(missing=True)
        self.assertEqual("partial", result["status"])
        self.assertEqual(["direction_dominance"],
                         [item["type"] for item in result["observations"]])

    def test_upstream_hash_mismatch_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "m01.json"
            upstream.write_text("original", encoding="utf-8")
            source = root / "m09.json"
            source.write_text(json.dumps(features(upstream)), encoding="utf-8")
            upstream.write_text("tampered", encoding="utf-8")
            output = root / "out"
            with self.assertRaises(ValueError):
                M10.analyze(source, output)
            self.assertFalse(output.exists())

    def test_invalid_schema_and_thresholds_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "m01.json"
            upstream.write_text("evidence", encoding="utf-8")
            value = features(upstream)
            value["flows"][0]["unexpected"] = True
            source = root / "m09.json"
            source.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(jsonschema.ValidationError):
                M10.analyze(source, root / "out")
        for parameters in ({"dominance": 1.1}, {"periodic_cv": math.nan},
                           {"minimum_iats": 0}, {"burst_packets": 0}):
            with self.subTest(parameters=parameters):
                with self.assertRaises(ValueError):
                    self.analyze_fixture(**parameters)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "m09.json"
            source.write_text("{}", encoding="utf-8")
            output = root / "out"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                M10.analyze(source, output)

    def test_result_validates_against_strict_module_schema(self):
        schema = json.loads((ROOT / "research" / "M10-behavior-analysis" /
                             "behaviors.schema.json").read_text(encoding="utf-8"))
        result = self.analyze_fixture()
        jsonschema.validate(result, schema)
        invalid = json.loads(json.dumps(result))
        invalid["observations"][0]["unexpected"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


if __name__ == "__main__":
    unittest.main()

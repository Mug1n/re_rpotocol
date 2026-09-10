from __future__ import annotations

import importlib.util
import json
import math
import tempfile
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(value)
    return value


M09 = load_module("m09", ROOT / "experiments" / "M09" / "run.py")


def m01(missing_time: bool = False) -> dict:
    source_id = "fixture-source"
    packets = []
    values = (("1.0", "a", "b", 10), ("1.1", "b", "a", 20),
              ("1.2", "a", "b", 30), ("1.3", "a", "b", 40))
    for index, (time, source, destination, size) in enumerate(values):
        packets.append({
            "id": f"p{index}", "source_id": source_id, "index": index,
            "timestamp_epoch": None if missing_time and index == 2 else time,
            "interface_id": 0, "captured_length": size, "original_length": size,
            "truncated": False, "source_file_offset": index,
            "source_offset_reason": None, "tcp_stream": 0,
            "src_ip": source, "src_port": 1 if source == "a" else 2,
            "dst_ip": destination, "dst_port": 1 if destination == "a" else 2,
            "tcp_seq_raw": index * 10, "tcp_payload_length": size,
            "payload_ref": None,
            "analysis": {"retransmission": False, "out_of_order": False,
                         "gap_or_loss": False},
        })
    return {
        "schema_version": "0.1", "id": source_id, "path": "fixture.pcap",
        "sha256": "0" * 64, "length": 100, "format": "pcap",
        "format_evidence": [{"rule_id": "fixture", "observation": "test"}],
        "metadata_availability": {"packet_boundaries": True, "network_headers": True,
                                  "flow_identity": True, "direction": True,
                                  "timestamps": "partial" if missing_time else True},
        "status": "partial" if missing_time else "ok", "byte_ranges": [],
        "packets": packets,
        "flows": [{
            "id": "f1", "source_id": source_id, "transport": "tcp", "tcp_stream": 0,
            "node0": {"ip": "a", "port": 1}, "node1": {"ip": "b", "port": 2},
            "packet_ids": [packet["id"] for packet in packets],
            "first_timestamp_epoch": "1.0", "last_timestamp_epoch": "1.3",
        }],
        "streams": [], "warnings": [],
    }


def raw_m01() -> dict:
    value = m01()
    value.update({"format": "raw_bytes", "length": 0, "status": "empty",
                  "packets": [], "flows": [], "streams": []})
    value["metadata_availability"] = {
        "packet_boundaries": False, "network_headers": False, "flow_identity": False,
        "direction": False, "timestamps": False}
    return value


class M09Tests(unittest.TestCase):
    def analyze_fixture(self, value: dict, **parameters):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "m01.json"
            source.write_text(json.dumps(value), encoding="utf-8")
            return M09.analyze(source, root / "out", **parameters)

    def test_bidirectional_statistics_are_hand_calculable(self):
        flow = self.analyze_fixture(m01())["flows"][0]
        self.assertEqual(100, flow["byte_count"])
        self.assertEqual(80, flow["directional"]["node0_to_node1"]["bytes"])
        self.assertAlmostEqual(0.3, flow["duration_seconds"])
        self.assertEqual(4, flow["burst"]["max_packets"])

    def test_missing_time_is_explicit(self):
        result = self.analyze_fixture(m01(True))
        self.assertEqual("partial", result["status"])
        self.assertIsNone(result["flows"][0]["duration_seconds"])
        self.assertTrue(result["unavailable_features"])

    def test_raw_input_is_insufficient_metadata(self):
        self.assertEqual("insufficient_metadata", self.analyze_fixture(raw_m01())["status"])

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "m.json"
            source.write_text(json.dumps(m01()), encoding="utf-8")
            output = root / "out"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                M09.analyze(source, output)

    def test_invalid_m01_schema_and_references_leave_no_output(self):
        for mutate in (
            lambda value: value["packets"][0].pop("source_id"),
            lambda value: value["packets"][0].update(source_id="wrong"),
        ):
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    value = m01()
                    mutate(value)
                    source = root / "m01.json"
                    source.write_text(json.dumps(value), encoding="utf-8")
                    output = root / "out"
                    with self.assertRaises((ValueError, jsonschema.ValidationError)):
                        M09.analyze(source, output)
                    self.assertFalse(output.exists())

    def test_non_finite_or_invalid_parameters_are_rejected(self):
        with self.assertRaises(ValueError):
            self.analyze_fixture(m01(), burst_gap_seconds=math.inf)
        with self.assertRaises(ValueError):
            self.analyze_fixture(m01(), retransmission_policy="maybe")

    def test_result_validates_against_strict_module_schema(self):
        schema = json.loads((ROOT / "research" / "M09-flow-features" /
                             "flow-features.schema.json").read_text(encoding="utf-8"))
        result = self.analyze_fixture(m01())
        jsonschema.validate(result, schema)
        invalid = json.loads(json.dumps(result))
        invalid["flows"][0]["unexpected"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


if __name__ == "__main__":
    unittest.main()

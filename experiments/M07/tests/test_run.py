from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M07" / "run.py"
SCHEMA_PATH = ROOT / "research" / "M07-standard-protocols" / "protocols.schema.json"
FAKE_RESPONSE = ROOT / "experiments" / "M07" / "fixtures" / "tshark-http-tls.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m07_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProtocolAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def make_input(self, root: Path, *, capture: bool = True) -> Path:
        payload = b"capture bytes" if capture else b"raw bytes"
        source = root / ("capture.pcapng" if capture else "input.dat")
        source.write_bytes(payload)
        artifact = {
            "schema_version": "0.1", "id": "m01-fixture", "path": str(source),
            "sha256": hashlib.sha256(payload).hexdigest(), "length": len(payload),
            "format": "pcapng" if capture else "raw_bytes",
            "format_evidence": [{"rule_id": "fixture", "observation": "test"}],
            "metadata_availability": {"packet_boundaries": capture, "network_headers": capture, "flow_identity": capture, "direction": capture, "timestamps": capture},
            "status": "ok", "byte_ranges": [],
            "packets": ([{"id": "m01-fixture-packet-1", "source_id": "m01-fixture", "index": 0, "timestamp_epoch": "1.0", "interface_id": 0, "captured_length": 64, "original_length": 64, "truncated": False, "source_file_offset": 0, "source_offset_reason": None, "tcp_stream": 0, "src_ip": "192.0.2.1", "src_port": 12345, "dst_ip": "192.0.2.2", "dst_port": 8443, "tcp_seq_raw": 1, "tcp_payload_length": 8, "payload_ref": None, "analysis": {"retransmission": False, "out_of_order": False, "gap_or_loss": False}}] if capture else []),
            "flows": [], "streams": [], "warnings": []
        }
        path = root / "result.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def fake_runner(self, command, **kwargs):
        if "-v" in command:
            return subprocess.CompletedProcess(command, 0, "TShark 4.6.6\n", "")
        return subprocess.CompletedProcess(command, 0, FAKE_RESPONSE.read_text(encoding="utf-8"), "")

    def test_http_and_tls_fields_are_normalized_without_claiming_plaintext(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root), root / "out", tshark_path=Path("fake-tshark"), runner=self.fake_runner
            )
            jsonschema.validate(result, self.schema)
            self.assertEqual("ok", result["status"])
            self.assertEqual(["http", "tls"], [item["protocol"] for item in result["observations"]])
            tls = result["observations"][1]
            self.assertEqual("metadata_only", tls["visibility"])
            self.assertIn("application plaintext", " ".join(tls["limitations"]))
            self.assertNotIn("8443", json.dumps(tls["field_evidence"]))

    def test_decode_as_is_recorded_as_recognition_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root), root / "out", tshark_path=Path("fake-tshark"),
                decode_as=["tcp.port==8443,http"], runner=self.fake_runner
            )
            self.assertTrue(all(item["recognition_mode"] == "decode_as" for item in result["observations"]))
            self.assertEqual(["tcp.port==8443,http"], result["parameters"]["decode_as"])

    def test_raw_input_is_not_applicable_without_running_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(self.make_input(root, capture=False), root / "out", runner=lambda *a, **k: self.fail("tool invoked"))
            jsonschema.validate(result, self.schema)
            self.assertEqual("not_applicable", result["status"])

    def test_missing_tool_is_a_machine_readable_degradation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(self.make_input(root), root / "out", tshark_path=root / "missing.exe")
            jsonschema.validate(result, self.schema)
            self.assertEqual("tool_unavailable", result["status"])
            self.assertEqual("TSHARK_UNAVAILABLE", result["unknown_scopes"][0]["reason_code"])

    def test_malformed_tool_json_leaves_no_output(self):
        def malformed(command, **kwargs):
            if "-v" in command:
                return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
            return subprocess.CompletedProcess(command, 0, "not-json", "")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "out"
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                self.module.analyze_protocols(self.make_input(root), output, tshark_path=Path("fake"), runner=malformed)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

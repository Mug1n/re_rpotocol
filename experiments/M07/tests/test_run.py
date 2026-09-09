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

    def make_input(self, root: Path, *, capture: bool = True, packet_count: int = 1, payload: bytes | None = None) -> Path:
        payload = payload if payload is not None else (b"capture bytes" if capture else b"raw bytes")
        source = root / ("capture.pcapng" if capture else "input.dat")
        source.write_bytes(payload)
        artifact = {
            "schema_version": "0.1", "id": "m01-fixture", "path": str(source),
            "sha256": hashlib.sha256(payload).hexdigest(), "length": len(payload),
            "format": "pcapng" if capture else "raw_bytes",
            "format_evidence": [{"rule_id": "fixture", "observation": "test"}],
            "metadata_availability": {"packet_boundaries": capture, "network_headers": capture, "flow_identity": capture, "direction": capture, "timestamps": capture},
            "status": "ok", "byte_ranges": [],
            "packets": ([{"id": f"m01-fixture-packet-{index + 1}", "source_id": "m01-fixture", "index": index, "timestamp_epoch": "1.0", "interface_id": 0, "captured_length": 64, "original_length": 64, "truncated": False, "source_file_offset": 0, "source_offset_reason": None, "tcp_stream": 0, "src_ip": "192.0.2.1", "src_port": 12345, "dst_ip": "192.0.2.2", "dst_port": 8443, "tcp_seq_raw": 1, "tcp_payload_length": 8, "payload_ref": None, "analysis": {"retransmission": False, "out_of_order": False, "gap_or_loss": False}} for index in range(packet_count)] if capture else []),
            "flows": [], "streams": [], "warnings": []
        }
        path = root / "result.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def field_row(self, frame_number: int, *, protocols: str = "eth:ip:tcp:http:tls") -> str:
        values = {"frame.number": str(frame_number), "frame.protocols": protocols,
                  "http.request.method": "GET", "http.host": "example.test",
                  "http.request.uri": "/", "http.content_type": "text/plain",
                  "tls.handshake.type": "1", "tls.handshake.version": "0x0303"}
        return "\t".join(values.get(field, "") for field in self.module._tshark_fields()) + "\n"

    def fake_runner(self, command, **kwargs):
        if "-v" in command:
            return subprocess.CompletedProcess(command, 0, "TShark 4.6.6\n", "")
        return subprocess.CompletedProcess(command, 0, self.field_row(1), "")

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

    def test_decode_as_is_only_attributed_to_matching_protocol(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root), root / "out", tshark_path=Path("fake-tshark"),
                decode_as=["tcp.port==8443,http"], runner=self.fake_runner
            )
            modes = {item["protocol"]: item["recognition_mode"] for item in result["observations"]}
            self.assertEqual({"http": "decode_as", "tls": "dissector"}, modes)
            self.assertEqual(["tcp.port==8443,http"], result["parameters"]["decode_as"])

    def test_timeout_writes_schema_valid_degradation_without_partial_observations(self):
        def timeout_runner(command, **kwargs):
            self.assertEqual(0.01, kwargs["timeout"])
            if "-v" in command:
                return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=self.field_row(1))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root), root / "out", tshark_path=Path("fake"),
                runner=timeout_runner, timeout_seconds=0.01,
            )
            jsonschema.validate(result, self.schema)
            self.assertEqual("tool_unavailable", result["status"])
            self.assertEqual([], result["observations"])
            self.assertEqual("TSHARK_TIMEOUT", result["unknown_scopes"][0]["reason_code"])

    def test_observation_budget_returns_explicit_partial_result(self):
        def many_records(command, **kwargs):
            if "-v" in command:
                return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
            return subprocess.CompletedProcess(command, 0, "".join(self.field_row(i) for i in range(1, 4)), "")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root, packet_count=3), root / "out", tshark_path=Path("fake"),
                runner=many_records, max_observations=1,
            )
            jsonschema.validate(result, self.schema)
            self.assertEqual("partial", result["status"])
            self.assertEqual(1, len(result["observations"]))
            self.assertEqual("TSHARK_OBSERVATION_LIMIT", result["unknown_scopes"][0]["reason_code"])

    def test_capture_size_budget_stops_before_tshark(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root, payload=b"0123456789"), root / "out",
                tshark_path=Path("fake"), runner=lambda *a, **k: self.fail("tool invoked"),
                max_capture_bytes=4,
            )
            jsonschema.validate(result, self.schema)
            self.assertEqual("partial", result["status"])
            self.assertEqual("CAPTURE_BYTES_LIMIT", result["unknown_scopes"][0]["reason_code"])

    def test_tshark_output_budget_rejects_all_unparsed_output(self):
        def oversized(command, **kwargs):
            if "-v" in command:
                return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
            return subprocess.CompletedProcess(command, 0, self.field_row(1), "")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.module.analyze_protocols(
                self.make_input(root), root / "out", tshark_path=Path("fake"), runner=oversized,
                max_tshark_output_bytes=4,
            )
            self.assertEqual("partial", result["status"])
            self.assertEqual([], result["observations"])
            self.assertEqual("TSHARK_OUTPUT_LIMIT", result["unknown_scopes"][0]["reason_code"])

    def test_tshark_reads_verified_private_snapshot_when_source_is_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact_path = self.make_input(root)
            source = Path(json.loads(artifact_path.read_text(encoding="utf-8"))["path"])
            original = source.read_bytes()

            def replacing_runner(command, **kwargs):
                if "-v" in command:
                    return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
                snapshot = Path(command[command.index("-r") + 1])
                source.write_bytes(b"replacement")
                self.assertNotEqual(source, snapshot)
                self.assertEqual(original, snapshot.read_bytes())
                return subprocess.CompletedProcess(command, 0, self.field_row(1), "")

            result = self.module.analyze_protocols(
                artifact_path, root / "out", tshark_path=Path("fake"), runner=replacing_runner
            )
            self.assertEqual("ok", result["status"])

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
            return subprocess.CompletedProcess(command, 0, "not-a-frame\teth:ip:http\n", "")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "out"
            with self.assertRaisesRegex(RuntimeError, "valid frame.number"):
                self.module.analyze_protocols(self.make_input(root), output, tshark_path=Path("fake"), runner=malformed)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

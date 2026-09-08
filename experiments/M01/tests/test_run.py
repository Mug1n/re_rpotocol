from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M01" / "run.py"
FIXTURES = ROOT / "data" / "fixtures"
SCHEMA_PATH = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
GROUND_TRUTH_PATH = ROOT / "data" / "ground-truth" / "m01-ground-truth.json"
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
CAPINFOS = Path(r"C:\Program Files\Wireshark\capinfos.exe")


def load_module():
    spec = importlib.util.spec_from_file_location("m01_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProbeFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def probe(self, name: str):
        return self.module.probe_format(
            FIXTURES / name,
            capinfos_path=CAPINFOS if CAPINFOS.exists() else None,
        )

    def test_raw_dat_is_not_promoted_to_capture(self):
        result = self.probe("m01-raw.dat")
        self.assertEqual("raw_bytes", result.format)
        self.assertEqual("M01-FMT-NO-KNOWN-MAGIC", result.rule_id)

    def test_empty_dat_has_explicit_empty_reason(self):
        result = self.probe("m01-empty.dat")
        self.assertEqual("raw_bytes", result.format)
        self.assertEqual("M01-FMT-EMPTY", result.rule_id)

    def test_false_pcap_magic_is_rejected(self):
        result = self.probe("m01-false-pcap.dat")
        self.assertEqual("raw_bytes", result.format)
        self.assertIn("GLOBAL-HEADER-TRUNCATED", result.rule_id)

    def test_false_pcapng_magic_is_rejected_even_if_capinfos_exits_zero(self):
        result = self.probe("m01-false-pcapng.dat")
        self.assertEqual("raw_bytes", result.format)
        self.assertIn("HEADER-TRUNCATED", result.rule_id)

    def test_pcap_content_wins_over_dat_suffix(self):
        result = self.probe("m01-pcap-as-dat.dat")
        self.assertEqual("pcap", result.format)
        self.assertEqual("M01-FMT-PCAP-VALIDATED", result.rule_id)

    def test_pcapng_content_wins_over_dat_suffix(self):
        result = self.probe("m01-pcapng-as-dat.dat")
        self.assertEqual("pcapng", result.format)
        self.assertEqual("M01-FMT-PCAPNG-VALIDATED", result.rule_id)

    def test_raw_fixture_bytes_match_declared_ground_truth(self):
        truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))["fixtures"]
        for name in ("m01-raw.dat", "m01-raw.bin"):
            with self.subTest(name=name):
                self.assertEqual(
                    bytes.fromhex(truth[name]["payload_hex"]),
                    (FIXTURES / name).read_bytes(),
                )


class AnalyzeInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def analyze(self, name: str):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        output_dir = Path(temp.name) / "output"
        result = self.module.analyze_input(
            FIXTURES / name,
            output_dir,
            tshark_path=TSHARK,
            capinfos_path=CAPINFOS,
        )
        jsonschema.validate(result, self.schema)
        return result, output_dir

    def test_raw_dat_preserves_exact_bytes_and_null_network_metadata(self):
        result, output_dir = self.analyze("m01-raw.dat")
        self.assertEqual("raw_bytes", result["format"])
        self.assertEqual("ok", result["status"])
        self.assertEqual([], result["packets"])
        self.assertEqual([], result["flows"])
        self.assertEqual([], result["streams"])
        self.assertEqual(
            {
                "packet_boundaries": False,
                "network_headers": False,
                "flow_identity": False,
                "direction": False,
                "timestamps": False,
            },
            result["metadata_availability"],
        )
        payload = output_dir / result["byte_ranges"][0]["artifact_ref"]
        self.assertEqual(
            (FIXTURES / "m01-raw.dat").read_bytes(),
            payload.read_bytes(),
        )

    def test_empty_dat_is_valid_empty_input(self):
        result, _ = self.analyze("m01-empty.dat")
        self.assertEqual("empty", result["status"])
        self.assertEqual([], result["byte_ranges"])

    @unittest.skipUnless(TSHARK.exists() and CAPINFOS.exists(), "Wireshark CLI unavailable")
    def test_capture_dat_emits_packets_flows_and_exact_stream_payloads(self):
        result, output_dir = self.analyze("m01-pcapng-as-dat.dat")
        self.assertEqual("pcapng", result["format"])
        self.assertEqual("ok", result["status"])
        self.assertEqual(4, len(result["packets"]))
        self.assertEqual(1, len(result["flows"]))
        self.assertEqual(1, len(result["streams"]))
        directions = result["streams"][0]["directions"]
        observed = {
            item["direction"]: (output_dir / item["artifact_ref"]).read_bytes()
            for item in directions
        }
        self.assertEqual(b"HELLO WORLD!", observed["node0_to_node1"])
        self.assertEqual(b"ACK", observed["node1_to_node0"])

    @unittest.skipUnless(TSHARK.exists() and CAPINFOS.exists(), "Wireshark CLI unavailable")
    def test_retransmission_is_not_duplicated_in_reassembled_stream(self):
        result, output_dir = self.analyze("m01-reassembly.pcapng")
        stream = result["streams"][0]
        observed = {
            item["direction"]: (output_dir / item["artifact_ref"]).read_bytes()
            for item in stream["directions"]
        }
        self.assertEqual(b"HELLO WORLD!", observed["node0_to_node1"])
        self.assertEqual(b"ACK", observed["node1_to_node0"])
        self.assertGreaterEqual(stream["analysis"]["retransmission_packets"], 1)
        self.assertGreaterEqual(stream["analysis"]["gap_or_loss_packets"], 1)

    @unittest.skipUnless(TSHARK.exists() and CAPINFOS.exists(), "Wireshark CLI unavailable")
    def test_truncated_capture_is_explicitly_partial(self):
        result, _ = self.analyze("m01-truncated.pcapng")
        self.assertEqual("partial", result["status"])
        self.assertTrue(all(packet["truncated"] for packet in result["packets"]))
        self.assertTrue(all(packet["payload_ref"] is None for packet in result["packets"]))

    def test_missing_input_cli_fails_without_writing_result(self):
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "output"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    str(FIXTURES / "does-not-exist.dat"),
                    "--output-dir",
                    str(output_dir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, completed.returncode)
            self.assertIn("does not exist", completed.stderr)
            self.assertFalse((output_dir / "result.json").exists())

    @unittest.skipUnless(CAPINFOS.exists(), "capinfos unavailable")
    def test_capture_tool_failure_leaves_no_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "output"
            with self.assertRaises(FileNotFoundError):
                self.module.analyze_input(
                    FIXTURES / "m01-pcap-as-dat.dat",
                    output_dir,
                    tshark_path=Path(temp) / "missing-tshark.exe",
                    capinfos_path=CAPINFOS,
                )
            self.assertFalse(output_dir.exists())


if __name__ == "__main__":
    unittest.main()

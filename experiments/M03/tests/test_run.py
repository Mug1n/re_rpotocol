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
MODULE_PATH = ROOT / "experiments" / "M03" / "run.py"
GROUND_TRUTH = ROOT / "data" / "ground-truth" / "m03-framing.json"
SCHEMA_PATH = ROOT / "research" / "M03-framing" / "framing.schema.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m03_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))

    def test_length_rule_matches_complete_messages_and_preserves_all_other_bytes(self):
        case = self.truth["cases"]["length_prefixed"]
        data = bytes.fromhex(case["stream_hex"])
        messages, diagnostics, _ = self.module.frame_length_prefixed(
            data,
            stream_id="fixture",
            magic=bytes.fromhex(case["parameters"]["magic_hex"]),
            length_offset=case["parameters"]["length_offset"],
            length_width=case["parameters"]["length_width"],
            byteorder=case["parameters"]["byteorder"],
            length_mode=case["parameters"]["length_mode"],
            header_size=case["parameters"]["header_size"],
            trailer_size=case["parameters"]["trailer_size"],
            max_frame_length=case["parameters"]["max_frame_length"],
        )
        observed = [[item["start"], item["end"]] for item in messages]
        self.assertEqual(case["expected_messages"], observed)
        self.assertEqual(case["expected_unparsed"], [
            [item["start"], item["end"]]
            for item in self.module._unparsed_ranges(len(data), messages)
        ])
        self.assertTrue(any(item["rule_id"] == "M03-LEN-OUT-OF-RANGE" for item in diagnostics))
        self.assertTrue(any(item["rule_id"] == "M03-LEN-TRUNCATED-FRAME" for item in diagnostics))

    def test_embedded_magic_inside_accepted_payload_is_not_double_counted(self):
        case = self.truth["cases"]["length_prefixed"]
        data = bytes.fromhex(case["stream_hex"])
        messages, _, _ = self.module.frame_length_prefixed(
            data,
            stream_id="fixture",
            magic=bytes.fromhex("cafe"),
            length_offset=3,
            length_width=2,
            byteorder="big",
            length_mode="payload",
            header_size=5,
            trailer_size=1,
            max_frame_length=32,
        )
        self.assertEqual(3, len(messages))

    def test_boundary_metrics_are_exact_for_ground_truth(self):
        expected = [(2, 11), (11, 21), (28, 35)]
        metrics = self.module.evaluate_framing(expected, expected, stream_length=42)
        self.assertEqual(1.0, metrics["boundary_precision"])
        self.assertEqual(1.0, metrics["boundary_recall"])
        self.assertEqual(1.0, metrics["boundary_f1"])
        self.assertEqual(1.0, metrics["complete_message_match_rate"])

    def test_delimiter_rule_keeps_tail_unparsed(self):
        data = b"aa|bb|tail"
        messages, _, _ = self.module.frame_delimited(
            data, stream_id="fixture", delimiter=b"|"
        )
        self.assertEqual([(0, 3), (3, 6)], [(x["start"], x["end"]) for x in messages])
        self.assertEqual([(6, 10)], [
            (x["start"], x["end"]) for x in self.module._unparsed_ranges(len(data), messages)
        ])

    def test_fixed_rule_keeps_prefix_and_tail_unparsed(self):
        data = b"abcdefghij"
        messages, diagnostics, _ = self.module.frame_fixed(
            data, stream_id="fixture", frame_size=4, start_offset=1
        )
        self.assertEqual([(1, 5), (5, 9)], [(x["start"], x["end"]) for x in messages])
        self.assertEqual([(0, 1), (9, 10)], [
            (x["start"], x["end"]) for x in self.module._unparsed_ranges(len(data), messages)
        ])
        self.assertEqual("M03-FIXED-TRAILING-PARTIAL", diagnostics[-1]["rule_id"])

    def test_invalid_length_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            self.module.frame_length_prefixed(
                b"data",
                stream_id="fixture",
                length_offset=3,
                length_width=2,
                byteorder="big",
                length_mode="payload",
                header_size=4,
            )

    def test_automatic_inference_finds_repeated_type_length_payload_frames(self):
        data = b"\x01\x03abc\x02\x02de\x01\x04wxyz\x02\x01q"
        messages, diagnostics, parameters = self.module.infer_length_prefixed(
            data, stream_id="private", min_frames=3, max_header_size=6
        )
        self.assertEqual([(0, 5), (5, 9), (9, 15), (15, 18)], [
            (item["start"], item["end"]) for item in messages
        ])
        self.assertEqual("M03-INFERRED-LENGTH-PREFIX", diagnostics[0]["rule_id"])
        self.assertEqual(1, parameters["selected"]["length_offset"])

    def test_automatic_inference_refuses_non_repeating_bytes(self):
        messages, diagnostics, parameters = self.module.infer_length_prefixed(
            b"\x00\xff\x10\x93\x81\x00\x7f", stream_id="private", min_frames=3
        )
        self.assertEqual([], messages)
        self.assertEqual("M03-INFERENCE-INSUFFICIENT-EVIDENCE", diagnostics[0]["rule_id"])
        self.assertEqual(0, parameters["candidate_count"])


class CliTests(unittest.TestCase):
    def test_cli_writes_exact_message_artifacts_and_refuses_overwrite(self):
        case = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))["cases"]["length_prefixed"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "stream.dat"
            source.write_bytes(bytes.fromhex(case["stream_hex"]))
            output = root / "output"
            command = [
                sys.executable,
                str(MODULE_PATH),
                str(source),
                "--output-dir",
                str(output),
                "--rule",
                "length",
                "--magic-hex",
                "cafe",
                "--length-offset",
                "3",
                "--length-width",
                "2",
                "--header-size",
                "5",
                "--trailer-size",
                "1",
                "--max-frame-length",
                "32",
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, first.returncode)
            result = json.loads((output / "framing.json").read_text(encoding="utf-8"))
            jsonschema.validate(
                result,
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
            )
            self.assertEqual(3, len(result["messages"]))
            for message in result["messages"]:
                artifact = output / message["artifact_ref"]
                self.assertEqual(
                    source.read_bytes()[message["start"] : message["end"]],
                    artifact.read_bytes(),
                )
            self.assertEqual(2, second.returncode)
            self.assertIn("already exists", second.stderr)


if __name__ == "__main__":
    unittest.main()

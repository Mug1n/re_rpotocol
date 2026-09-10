from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_runner():
    path = ROOT / "scripts" / "evaluate_public_samples.py"
    spec = importlib.util.spec_from_file_location("public_sample_evaluation", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicSampleEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()

    def test_decode_hex_messages_rejects_invalid_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invalid.input"
            path.write_text("0011\nnot-hex\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "line 2"):
                self.runner.decode_hex_messages(path)

    def test_overall_report_keeps_not_applicable_distinct_from_failure(self):
        results = [
            {
                "artifact_id": "sample-a",
                "protocol": "Example",
                "category": "test",
                "input_path": "raw/sample-a.bin",
                "input_sha256": "a" * 64,
                "input_size": 4,
                "outcome": "completed_with_limits",
                "modules": {
                    "M01": {"status": "ok", "detail": "raw bytes"},
                    "M09": {"status": "not_applicable", "detail": "no timestamps"},
                },
                "highlights": [],
                "limitations": ["No capture metadata."],
            }
        ]
        report = self.runner.render_overall_report(results, generated_at="2026-09-09")
        self.assertIn("completed_with_limits", report)
        self.assertIn("not_applicable", report)
        self.assertNotIn("M09 failure", report)

    def test_capture_m02_uses_bounded_evaluation_windows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "capture.bin"
            source.write_bytes(bytes(range(256)) * 2400)
            module = self.runner.load_module(
                "m02_for_public_evaluation_test", ROOT / "experiments" / "M02" / "run.py"
            )
            artifact, _, _ = self.runner._m02_step(
                {"M02": module}, source, root / "m02"
            )
            output = root / "m02" / "features.json"
            self.assertEqual(self.runner.EVALUATION_M02_WINDOW_SIZE,
                             artifact["parameters"]["window_size"])
            self.assertLess(output.stat().st_size, 16 * 1024 * 1024)
            self.assertEqual(artifact, json.loads(output.read_text(encoding="utf-8")))

    def test_cli_accepts_explicit_tshark_path(self):
        parser = self.runner.build_parser()
        args = parser.parse_args([
            "--work-root", "work", "--report-root", "reports",
            "--tshark", "C:/Program Files/Wireshark/tshark.exe",
        ])
        self.assertEqual(Path("C:/Program Files/Wireshark/tshark.exe"), args.tshark)


if __name__ == "__main__":
    unittest.main()

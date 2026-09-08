from __future__ import annotations

import importlib.util
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M02" / "run.py"


def load_module():
    spec = importlib.util.spec_from_file_location("m02_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def analyze(self, data: bytes, **kwargs):
        return self.module.analyze_bytes(
            data,
            source_id="fixture",
            source_path="fixture.bin",
            source_sha256="0" * 64,
            **kwargs,
        )

    def test_empty_input_has_no_nan_or_division_by_zero(self):
        result = self.analyze(b"")
        self.assertEqual("empty", result["status"])
        self.assertIsNone(result["global"]["entropy_bits_per_byte"])
        self.assertIsNone(result["global"]["printable_ascii_ratio"])
        self.assertEqual(0.0, sum(result["global"]["byte_frequencies"]))
        self.assertEqual([], result["windows"])

    def test_all_zero_entropy_is_zero(self):
        result = self.analyze(bytes(256))
        self.assertEqual(0.0, result["global"]["entropy_bits_per_byte"])
        self.assertEqual(1.0, result["global"]["zero_ratio"])
        self.assertEqual(1.0, result["global"]["byte_frequencies"][0])

    def test_uniform_all_bytes_entropy_is_eight(self):
        result = self.analyze(bytes(range(256)))
        self.assertTrue(
            math.isclose(8.0, result["global"]["entropy_bits_per_byte"], abs_tol=1e-12)
        )
        self.assertTrue(
            math.isclose(1.0, sum(result["global"]["byte_frequencies"]), abs_tol=1e-12)
        )

    def test_ascii_and_whitespace_are_counted_separately(self):
        result = self.analyze(b"ABC\n")
        self.assertEqual(0.75, result["global"]["printable_ascii_ratio"])
        self.assertEqual(0.25, result["global"]["ascii_whitespace_ratio"])

    def test_overlapping_repeated_pattern_offsets_are_preserved(self):
        result = self.analyze(b"ABABAB", ngram_sizes=(2,), pattern_limit=10)
        pattern = next(
            item for item in result["global"]["repeated_patterns"] if item["hex"] == "4142"
        )
        self.assertEqual(3, pattern["count"])
        self.assertEqual([0, 2, 4], pattern["offsets"])

    def test_short_tail_window_is_included(self):
        result = self.analyze(b"0123456789", window_size=4, window_step=4)
        self.assertEqual([(0, 4), (4, 8), (8, 10)], [
            (item["start"], item["end"]) for item in result["windows"]
        ])

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            self.analyze(b"data", window_size=0)


class CliTests(unittest.TestCase):
    def test_cli_writes_features_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.dat"
            source.write_bytes(b"HELLO")
            output = root / "output"
            command = [sys.executable, str(MODULE_PATH), str(source), "--output-dir", str(output)]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, first.returncode)
            self.assertTrue((output / "features.json").is_file())
            self.assertEqual(2, second.returncode)
            self.assertIn("already exists", second.stderr)


if __name__ == "__main__":
    unittest.main()

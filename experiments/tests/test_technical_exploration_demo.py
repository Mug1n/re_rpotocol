from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

from scripts.run_technical_exploration_demo import run_demo


class TechnicalExplorationDemoTests(unittest.TestCase):
    def test_real_dat_and_validated_recovery_create_a_single_report(self):
        dat = ROOT / "data" / "external" / "raw" / "watchpat" / "testdata.dat"
        recovery_input = ROOT / "experiments" / "M08" / "fixtures" / "nested-base64-gzip.dat"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "demo"
            summary = run_demo(dat, recovery_input, output)
            self.assertEqual("complete", summary["status"])
            self.assertEqual("complete", json.loads((output / "unknown_dat" / "run_manifest.json").read_text(encoding="utf-8"))["status"])
            self.assertGreater(summary["recovery"]["recovery_count"], 0)
            self.assertEqual("not_requested", summary["capture"]["status"])
            self.assertTrue((output / "technical_exploration_report.md").is_file())

    def test_capture_requires_an_explicit_tshark_path(self):
        dat = ROOT / "data" / "external" / "raw" / "watchpat" / "testdata.dat"
        recovery_input = ROOT / "experiments" / "M08" / "fixtures" / "nested-base64-gzip.dat"
        capture = ROOT / "data" / "external" / "raw" / "wireshark-v4.6.0" / "http-brotli.pcapng"
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "requires --tshark"):
                run_demo(dat, recovery_input, Path(temp) / "demo", capture_path=capture)

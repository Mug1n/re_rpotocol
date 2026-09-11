#!/usr/bin/env python3
"""Integration coverage for the real UBX held-out corpus builder."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.prepare_wireshark_ubx_truth import prepare


ROOT = Path(__file__).resolve().parents[2]
PCAP = ROOT / "data" / "external" / "wireshark-ubx-true" / "ubx_sample.pcap"
TSHARK = Path(r"D:\新建文件夹 (2)\Wireshark\tshark.exe")


@unittest.skipUnless(PCAP.is_file() and TSHARK.is_file(), "real UBX capture or TShark is unavailable")
class WiresharkUbxTruthTest(unittest.TestCase):
    def test_truth_is_bound_and_held_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "corpus"
            manifest = prepare(PCAP, TSHARK, output)
            truth = json.loads((output / "held_out.truth.json").read_text(encoding="utf-8"))
            self.assertGreater(manifest["selection"]["held_out_frame_count"], 100)
            self.assertEqual(len(truth["messages"]), manifest["selection"]["held_out_frame_count"])
            self.assertEqual(truth["messages"][0]["start"], 0)
            self.assertEqual(truth["messages"][-1]["end"], (output / "held_out.ubx.bin").stat().st_size)


if __name__ == "__main__":
    unittest.main()

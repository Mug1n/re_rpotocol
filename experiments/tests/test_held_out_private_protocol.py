from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "evaluate_unknown_private_protocol.py"

def load_module():
    spec = importlib.util.spec_from_file_location("held_out_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

class HeldOutPrivateProtocolTests(unittest.TestCase):
    def test_truth_is_scored_only_after_label_free_analysis(self):
        module = load_module()
        data = b"\x01\x03abc\x02\x02de\x01\x03abc\x02\x02de\x01\x03abc\x02\x02de"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "held-out.bin"; source.write_bytes(data)
            messages = []; offset = 0
            for index, (kind, size) in enumerate((("alpha", 5), ("beta", 4)) * 3):
                messages.append({"id": f"m{index}", "start": offset, "end": offset + size, "type": kind,
                                 "fields": [{"start": offset, "end": offset + 1}, {"start": offset + 1, "end": offset + 2}, {"start": offset + 2, "end": offset + size}]})
                offset += size
            truth = {"schema_version": "0.1", "corpus_id": "controlled-held-out-private-stream", "input_sha256": hashlib.sha256(data).hexdigest(), "messages": messages}
            truth_path = root / "truth.json"; truth_path.write_text(json.dumps(truth), encoding="utf-8")
            report = module.evaluate(source, truth_path, ROOT / "profiles" / "unknown-private.json", root / "output")
            self.assertTrue(report["truth_used_after_analysis"])
            self.assertEqual(1.0, report["boundary_metrics"]["boundary_f1"])
            self.assertEqual(1.0, report["type_metrics"]["ari"])
            self.assertEqual([], report["ambiguity"]["unparsed_ranges"])

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ANALYZE_PATH = ROOT / "scripts" / "analyze.py"


def load_analyzer():
    spec = importlib.util.spec_from_file_location("unknown_private_analyze", ANALYZE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load analyzer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class UnknownPrivatePipelineTests(unittest.TestCase):
    def test_unknown_profile_frames_clusters_aligns_and_infers_fields_without_truth(self):
        analyzer = load_analyzer()
        # Six self-contained private messages: type, payload length, payload.
        # Repeated type-specific messages give M04/M05 enough unlabeled support.
        data = b"\x01\x03abc\x02\x02de\x01\x03abc\x02\x02de\x01\x03abc\x02\x02de"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "unknown-private.bin"
            source.write_bytes(data)
            output = root / "analysis"
            result = analyzer.run_pipeline(source, output, ROOT / "profiles" / "unknown-private.json")
            self.assertEqual("complete", result["status"])
            framing = json.loads((output / "m03" / "framing.json").read_text(encoding="utf-8"))
            self.assertEqual("complete", framing["status"])
            self.assertEqual(6, len(framing["messages"]))
            self.assertEqual("M03-INFERRED-LENGTH-PREFIX", framing["diagnostics"][0]["rule_id"])
            clusters = json.loads((output / "m04" / "clusters.json").read_text(encoding="utf-8"))
            self.assertEqual(6, clusters["source"]["message_count"])
            formats = json.loads((output / "m06" / "format.json").read_text(encoding="utf-8"))
            self.assertGreater(formats["metrics"]["field_candidate_count"], 0)

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts import reproduce_iscx_evaluation as reproduction


class IscxReproductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(reproduction.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        cls.evaluation = json.loads(reproduction.DEFAULT_EVALUATION.read_text(encoding="utf-8"))

    def test_committed_evidence_is_internally_consistent(self):
        summary = reproduction.validate_evidence(self.manifest, self.evaluation)
        self.assertEqual(summary["sessions_used"], 28)
        self.assertEqual(summary["rows"], 1028)

    def test_metric_tampering_is_rejected(self):
        evaluation = copy.deepcopy(self.evaluation)
        evaluation["results"]["folds"][0]["macro_f1"] += 0.01
        with self.assertRaisesRegex(reproduction.EvidenceError, "macro-F1"):
            reproduction.validate_evidence(self.manifest, evaluation)

    def test_session_in_two_test_folds_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        used = next(item for item in manifest["sessions"] if item["used_in_evaluation"])
        used["held_out_in_folds"] = ["f1", "f2"]
        with self.assertRaisesRegex(reproduction.EvidenceError, "exactly once"):
            reproduction.validate_evidence(manifest, self.evaluation)

    def test_capture_discovery_rejects_ambiguity(self):
        sessions = [{"session_id": "vpn_demo"}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a" / "vpn_demo.pcap").write_bytes(b"pcap-a")
            (root / "b" / "VPN_DEMO.pcapng").write_bytes(b"pcap-b")
            with self.assertRaisesRegex(reproduction.EvidenceError, "exactly one"):
                reproduction._find_captures(root, sessions)


if __name__ == "__main__":
    unittest.main()

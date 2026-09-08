from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "experiments" / "tests" / "fixtures" / "contracts" / "m01-complete.json"
M07_FAKE = ROOT / "experiments" / "M07" / "fixtures" / "tshark-http-tls.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DeveloperAPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m01 = load_module("integration_m01", ROOT / "experiments" / "M01" / "run.py")
        cls.m07 = load_module("integration_m07", ROOT / "experiments" / "M07" / "run.py")
        cls.m08 = load_module("integration_m08", ROOT / "experiments" / "M08" / "run.py")
        cls.m12 = load_module("integration_m12", ROOT / "experiments" / "M12" / "run.py")

    def test_raw_bytes_flow_through_m01_m08_and_partial_m12_without_network_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.dat"
            source.write_bytes(b"48656c6c6f21")
            m01_dir = root / "m01"
            m01 = self.m01.analyze_input(source, m01_dir)
            payload = m01_dir / m01["byte_ranges"][0]["artifact_ref"]
            m08_dir = root / "m08"
            m08 = self.m08.analyze_recovery(payload, m08_dir, expected_sha256=hashlib.sha256(payload.read_bytes()).hexdigest(), source_module="M01", source_record_id=m01["id"])
            self.assertTrue(m08["recoveries"])
            m12_dir = root / "m12"
            manifest = self.m12.build_report({"M01": m01_dir / "result.json", "M08": m08_dir / "recovery.json"}, m12_dir)
            report = (m12_dir / "report.md").read_text(encoding="utf-8")
            self.assertEqual("partial", manifest["status"])
            self.assertIn("Unavailable or partial metadata", report)
            self.assertNotIn("client", report.lower())
            self.assertNotIn("server", report.lower())

    def test_capture_protocol_evidence_reaches_m12_with_resolvable_ids(self):
        def fake_runner(command, **kwargs):
            if "-v" in command:
                return subprocess.CompletedProcess(command, 0, "TShark fake\n", "")
            return subprocess.CompletedProcess(command, 0, M07_FAKE.read_text(encoding="utf-8"), "")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            capture = root / "capture.pcapng"
            capture.write_bytes(b"fixture capture")
            artifact = copy.deepcopy(json.loads(CONTRACT.read_text(encoding="utf-8")))
            artifact["path"] = str(capture)
            artifact["sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
            m01_path = root / "m01.json"
            m01_path.write_text(json.dumps(artifact), encoding="utf-8")
            m07_dir = root / "m07"
            self.m07.analyze_protocols(m01_path, m07_dir, tshark_path=Path("fake"), runner=fake_runner)
            m12_dir = root / "m12"
            manifest = self.m12.build_report({"M01": m01_path, "M07": m07_dir / "protocols.json"}, m12_dir)
            evidence = json.loads((m12_dir / "evidence.json").read_text(encoding="utf-8"))
            ids = {item["evidence_id"] for item in evidence}
            self.assertEqual(ids, set(manifest["sections"]["observed_facts"]))
            self.assertTrue(any(item["module"] == "M07" and "Protocol http" in item["observation"] for item in evidence))


if __name__ == "__main__":
    unittest.main()

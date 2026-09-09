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
        cls.m09 = load_module("integration_m09", ROOT / "experiments" / "M09" / "run.py")
        cls.m10 = load_module("integration_m10", ROOT / "experiments" / "M10" / "run.py")
        cls.m11 = load_module("integration_m11", ROOT / "experiments" / "M11" / "run.py")
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

    def test_m01_flow_reaches_m09_m10_and_m12_with_verified_hash_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            capture = root / "capture.pcapng"
            capture.write_bytes(b"fixture capture")
            artifact = copy.deepcopy(json.loads(CONTRACT.read_text(encoding="utf-8")))
            artifact["path"] = str(capture)
            artifact["sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
            m01_path = root / "m01.json"
            m01_path.write_text(json.dumps(artifact), encoding="utf-8")

            m09_dir = root / "m09"
            m09 = self.m09.analyze(m01_path, m09_dir)
            self.assertEqual("ok", m09["status"])
            self.assertEqual(["flow-0"], [flow["flow_id"] for flow in m09["flows"]])

            m10_dir = root / "m10"
            m10 = self.m10.analyze(m09_dir / "flow_features.json", m10_dir)
            self.assertEqual("ok", m10["status"])
            self.assertTrue(m10["observations"])

            m12_dir = root / "m12"
            self.m12.build_report(
                {
                    "M01": m01_path,
                    "M09": m09_dir / "flow_features.json",
                    "M10": m10_dir / "behaviors.json",
                },
                m12_dir,
            )
            evidence = json.loads((m12_dir / "evidence.json").read_text(encoding="utf-8"))
            self.assertTrue(any(item["module"] == "M09" and item["scope"]["id"] == "flow-0" for item in evidence))
            self.assertTrue(any(item["module"] == "M10" and item["scope"]["id"] == "flow-0" for item in evidence))

    def test_grouped_m11_evaluation_reaches_m12_without_becoming_a_network_claim(self):
        rows = []
        for index in range(12):
            label = "alpha" if index % 2 else "beta"
            rows.append(
                {
                    "id": f"row-{index}",
                    "group_id": f"group-{index}",
                    "labels": {"application": label},
                    "features": {
                        "bytes": 100 if label == "alpha" else 1,
                        "packets": 10 if label == "alpha" else 1,
                    },
                }
            )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dataset = root / "rows.json"
            dataset.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "feature_definition_version": "0.1",
                        "rows": rows,
                    }
                ),
                encoding="utf-8",
            )
            m11_dir = root / "m11"
            classification = self.m11.analyze(dataset, m11_dir, task="application")
            self.assertEqual("ok", classification["status"])
            self.assertEqual([], classification["split"]["group_overlap"])

            m12_dir = root / "m12"
            self.m12.build_report({"M11": m11_dir / "classification.json"}, m12_dir)
            evidence = json.loads((m12_dir / "evidence.json").read_text(encoding="utf-8"))
            m11_evidence = [item for item in evidence if item["module"] == "M11"]
            self.assertTrue(m11_evidence)
            self.assertTrue(all(item["scope"]["type"] == "evaluation_scope" for item in m11_evidence))
            self.assertTrue(all(item["method"] == "M11 grouped evaluation classifier" for item in m11_evidence))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M12" / "run.py"
EVIDENCE_SCHEMA = ROOT / "research" / "M12-llm" / "evidence.schema.json"
MANIFEST_SCHEMA = ROOT / "research" / "M12-llm" / "report-manifest.schema.json"
M01_FIXTURE = ROOT / "experiments" / "tests" / "fixtures" / "contracts" / "m01-complete.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m12_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.evidence_schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        cls.manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

    def make_m07(self, root: Path, *, wrong_hash: bool = False) -> Path:
        m01_hash = hashlib.sha256(M01_FIXTURE.read_bytes()).hexdigest()
        artifact = {
            "schema_version": "0.1",
            "source": {"module": "M01", "artifact_path": str(M01_FIXTURE), "artifact_sha256": "0" * 64 if wrong_hash else m01_hash, "record_id": "fixture-capture", "schema_version": "0.1"},
            "status": "ok", "parameters": {"decode_as": [], "display_filter": None},
            "tool": {"path": "fake", "version": "fake 1"},
            "observations": [{"observation_id": "obs-http", "scope_type": "packet", "scope_id": "packet-1", "protocol": "http", "recognition_mode": "dissector", "visibility": "application_visible", "field_evidence": [{"field": "http.request.method", "value": "GET"}], "limitations": []}],
            "unknown_scopes": [], "artifacts": [],
            "metrics": {"observation_count": 1, "unknown_scope_count": 0}, "warnings": []
        }
        path = root / ("m07-bad.json" if wrong_hash else "m07.json")
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def test_mixed_inputs_produce_stable_order_hashes_and_valid_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m07 = self.make_m07(root)
            first = self.module.build_report({"M07": m07, "M01": M01_FIXTURE}, root / "first")
            second = self.module.build_report({"M01": M01_FIXTURE, "M07": m07}, root / "second")
            self.assertEqual((root / "first" / "report.md").read_bytes(), (root / "second" / "report.md").read_bytes())
            self.assertEqual(first["report_sha256"], second["report_sha256"])
            jsonschema.validate(first, self.manifest_schema)
            for item in json.loads((root / "first" / "evidence.json").read_text(encoding="utf-8")):
                jsonschema.validate(item, self.evidence_schema)
            self.assertEqual(["M01", "M07"], [item["module"] for item in first["inputs"]])

    def test_missing_modules_create_partial_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.module.build_report({"M01": M01_FIXTURE}, root / "out")
            report = (root / "out" / "report.md").read_text(encoding="utf-8")
            self.assertEqual("partial", manifest["status"])
            self.assertIn("无法判断", report)
            self.assertIn("M07", report)

    def test_tampered_upstream_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                self.module.build_report({"M07": self.make_m07(root, wrong_hash=True)}, output)
            self.assertFalse(output.exists())

    def test_evidence_limit_is_deterministic_and_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.module.build_report({"M01": M01_FIXTURE, "M07": self.make_m07(root)}, root / "out", max_evidence=1)
            self.assertEqual(1, manifest["truncation"]["included"])
            self.assertGreater(manifest["truncation"]["omitted"], 0)

    def test_model_failure_or_unsupported_reference_does_not_block_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failed = self.module.build_report({"M01": M01_FIXTURE}, root / "failed", model_adapter=lambda evidence: (_ for _ in ()).throw(TimeoutError("offline")))
            unsupported = self.module.build_report({"M01": M01_FIXTURE}, root / "unsupported", model_adapter=lambda evidence: [{"text": "unsupported claim", "evidence_ids": ["missing"]}])
            self.assertEqual("deterministic", failed["generation_mode"])
            self.assertEqual("deterministic", unsupported["generation_mode"])
            self.assertTrue(any("model" in item.lower() for item in failed["warnings"]))
            self.assertNotIn("unsupported claim", (root / "unsupported" / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "analyze.py"
RUN_SCHEMA = ROOT / "research" / "run-manifest.schema.json"
FORMAL_RUN = ROOT / "reports" / "acceptance" / "2026-09-11-abc" / "run" / "run_manifest.json"
FORMAL_ACCEPTANCE = ROOT / "reports" / "acceptance" / "2026-09-11-abc" / "acceptance.json"


def load_module():
    spec = importlib.util.spec_from_file_location("acceptance_analyze", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AcceptancePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(path: Path, value: dict) -> Path:
        path.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))
        return path

    def portable_profile(self, root: Path) -> Path:
        return self.write_json(root / "profile.json", {
            "schema_version": "0.1", "profile_id": "test-portable",
            "description": "test profile", "stages": ["M01", "M02", "M08", "M12"],
        })

    def test_single_input_pipeline_writes_hash_bound_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.dat"
            source.write_bytes(b"portable test body\n")
            output = root / "run"
            result = self.module.run_pipeline(source, output, self.portable_profile(root))
            jsonschema.validate(result, self.schema)
            self.assertEqual("complete", result["status"])
            self.assertEqual({"M01", "M02", "M08", "M12"}, {
                item["module"] for item in result["artifacts"]
            })
            self.assertEqual("not_requested", result["model"]["status"])
            self.assertNotIn("truth", result)
            self.assertEqual(result, json.loads((output / "run_manifest.json").read_text(encoding="utf-8")))

    def test_stage_failure_is_atomic_and_machine_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.dat"
            source.write_bytes(b"bytes")
            profile = self.write_json(root / "profile.json", {
                "schema_version": "0.1", "profile_id": "bad-frame",
                "description": "force a real module error", "stages": ["M01", "M03"],
                "structure": {"source": "input", "rule": "fixed", "rule_origin": "manual_hypothesis",
                              "parameters": {"start_offset": 0, "frame_size": 0}},
            })
            output = root / "run"
            with self.assertRaises(ValueError):
                self.module.run_pipeline(source, output, profile)
            self.assertFalse(output.exists())
            failure = json.loads((root / "run.failure.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", failure["status"])
            self.assertEqual("M03", failure["stages"][-1]["stage"])
            self.assertEqual("failed", failure["stages"][-1]["status"])

    def test_reused_m01_must_match_supplied_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = root / "original.dat"
            original.write_bytes(b"original")
            self.module.analyze_input(original, root / "m01")
            other = root / "other.dat"
            other.write_bytes(b"different")
            profile = self.write_json(root / "profile.json", {
                "schema_version": "0.1", "profile_id": "reuse",
                "description": "reuse check", "stages": ["M01", "M12"],
                "reuse": {"m01": str(root / "m01" / "result.json")},
            })
            with self.assertRaisesRegex(ValueError, "does not describe"):
                self.module.run_pipeline(other, root / "run", profile)
            self.assertFalse((root / "run").exists())

    def test_existing_output_and_missing_input_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.dat"
            source.write_bytes(b"x")
            profile = self.portable_profile(root)
            output = root / "existing"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                self.module.run_pipeline(source, output, profile)
            with redirect_stderr(StringIO()):
                status = self.module.main([
                    "--input", str(root / "missing.dat"), "--profile", str(profile),
                    "--output-dir", str(root / "missing-run"),
                ])
            self.assertEqual(2, status)
            self.assertFalse((root / "missing-run").exists())

    def test_formal_abc_run_passes_independent_c_gate(self):
        from scripts import verify_acceptance

        run = json.loads(FORMAL_RUN.read_text(encoding="utf-8"))
        jsonschema.validate(run, self.schema)
        self.assertEqual("complete", run["status"])
        self.assertEqual({f"M{index:02d}" for index in range(1, 13)}, {
            item["module"] for item in run["artifacts"] if item["module"].startswith("M")
            and item["module"] != "M11_PREDICTION"
        })
        prediction_record = next(item for item in run["artifacts"] if item["module"] == "M11_PREDICTION")
        prediction = json.loads(Path(prediction_record["path"]).read_text(encoding="utf-8"))
        m01_record = next(item for item in run["artifacts"] if item["module"] == "M01")
        m01 = json.loads(Path(m01_record["path"]).read_text(encoding="utf-8-sig"))
        self.assertEqual({item["id"] for item in m01["flows"]}, {
            item["scope_id"] for item in prediction["predictions"]
        })
        self.assertEqual(("complete", "invoked"), verify_acceptance.verify(FORMAL_ACCEPTANCE))


if __name__ == "__main__":
    unittest.main()

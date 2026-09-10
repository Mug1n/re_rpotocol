from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "data" / "acceptance" / "frozen-20260910" / "full-chain" / "acceptance.json"
SCHEMA = ROOT / "research" / "acceptance.schema.json"
VERIFY = ROOT / "scripts" / "verify_acceptance.py"


def verifier_module():
    spec = importlib.util.spec_from_file_location("verify_acceptance_for_test", VERIFY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BehaviorAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = verifier_module()

    def test_full_chain_schema_and_independent_verifier_pass(self) -> None:
        manifest = json.loads(RUN.read_text(encoding="utf-8"))
        jsonschema.validate(manifest, json.loads(SCHEMA.read_text(encoding="utf-8")))
        self.assertEqual({f"M{i:02d}" for i in range(1, 12)}, set(manifest["input"]))
        self.assertEqual(("complete", "invoked"), self.verifier.verify(RUN))

    def test_missing_module_is_rejected_even_if_status_claims_complete(self) -> None:
        value = json.loads(RUN.read_text(encoding="utf-8"))
        del value["input"]["M11"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "acceptance.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "input modules"):
                self.verifier.verify(path)

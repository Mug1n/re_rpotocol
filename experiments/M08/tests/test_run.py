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
MODULE_PATH = ROOT / "experiments" / "M08" / "run.py"
SCHEMA_PATH = ROOT / "research" / "M08-recovery" / "recovery.schema.json"
NESTED_FIXTURE = ROOT / "experiments" / "M08" / "fixtures" / "nested-base64-gzip.txt"


def load_module():
    spec = importlib.util.spec_from_file_location("m08_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def analyze(self, data: bytes, **kwargs):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        source = root / "input.bin"
        source.write_bytes(data)
        output = root / "out"
        result = self.module.analyze_recovery(source, output, **kwargs)
        jsonschema.validate(result, self.schema)
        return result, output

    def test_nested_base64_then_gzip_preserves_full_chain_and_bytes(self):
        result, output = self.analyze(NESTED_FIXTURE.read_bytes().strip())
        nested = next(item for item in result["recoveries"] if [step["operation"] for step in item["transformation_chain"]] == ["base64", "gzip"])
        recovered = output / nested["output"]["artifact_ref"]
        self.assertEqual("恢复成功 recovery ok".encode(), recovered.read_bytes())
        self.assertEqual(hashlib.sha256(recovered.read_bytes()).hexdigest(), nested["output"]["sha256"])
        self.assertEqual("validated_magic", nested["basis"])

    def test_strict_hex_and_utf16_are_detected(self):
        hex_result, _ = self.analyze(b"48656c6c6f21")
        self.assertTrue(any(step["operation"] == "hex" for item in hex_result["recoveries"] for step in item["transformation_chain"]))
        utf_result, _ = self.analyze("你好".encode("utf-16"), min_printable_length=2)
        self.assertTrue(any(step["operation"] == "utf16" for item in utf_result["recoveries"] for step in item["transformation_chain"]))

    def test_invalid_base64_and_truncated_gzip_do_not_create_recovery(self):
        result, _ = self.analyze(b"H4sIAAAA====")
        self.assertTrue(result["failed_attempts"])
        gzip_result, _ = self.analyze(b"\x1f\x8b\x08\x00truncated")
        self.assertTrue(any(item["reason_code"] == "INVALID_COMPRESSED_STREAM" for item in gzip_result["failed_attempts"]))

    def test_output_and_inflation_limits_are_enforced(self):
        import gzip
        encoded = gzip.compress(b"A" * 4096, mtime=0)
        result, _ = self.analyze(encoded, max_output_bytes=128, max_inflation_ratio=4.0)
        self.assertTrue(any(item["reason_code"] in ("MAX_OUTPUT_BYTES", "MAX_INFLATION_RATIO") for item in result["failed_attempts"]))

    def test_tls_metadata_without_key_is_explicitly_skipped(self):
        result, _ = self.analyze(b"opaque ciphertext", encrypted_protocol="tls")
        self.assertTrue(any(item["reason_code"] == "ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL" for item in result["skipped_sources"]))
        self.assertNotEqual("ok", result["status"])

    def test_expected_source_hash_mismatch_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.bin"
            source.write_bytes(b"hello")
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                self.module.analyze_recovery(source, output, expected_sha256="0" * 64)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

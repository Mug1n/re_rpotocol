from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import gzip
import zlib
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
        encoded = gzip.compress(b"A" * 4096, mtime=0)
        result, _ = self.analyze(encoded, max_output_bytes=128, max_inflation_ratio=4.0)
        self.assertTrue(any(item["reason_code"] in ("MAX_OUTPUT_BYTES", "MAX_INFLATION_RATIO") for item in result["failed_attempts"]))

    def test_input_limit_is_checked_at_and_above_the_exact_boundary(self):
        result, _ = self.analyze(b"exact", max_input_bytes=5, max_output_bytes=5, max_depth=1)
        self.assertEqual(5, result["parameters"]["max_input_bytes"])

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.bin"
            source.write_bytes(b"too-big")
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "INPUT_EXCEEDS_MAX_BYTES"):
                self.module.analyze_recovery(source, output, max_input_bytes=6)
            self.assertFalse(output.exists())

    def test_max_depth_zero_and_n_bound_every_transformation_chain(self):
        depth_zero, _ = self.analyze(b"4869", max_depth=0)
        self.assertEqual([], depth_zero["recoveries"])
        self.assertTrue(any(item["reason_code"] == "MAX_RECURSION_DEPTH" for item in depth_zero["failed_attempts"]))

        depth_one, _ = self.analyze(b"4869", max_depth=1)
        self.assertTrue(any([step["operation"] for step in item["transformation_chain"]] == ["hex"] for item in depth_one["recoveries"]))
        self.assertTrue(all(len(item["transformation_chain"]) <= 1 for item in depth_one["recoveries"]))

        depth_two, _ = self.analyze(b"4869", max_depth=2, min_printable_length=2)
        self.assertTrue(any([step["operation"] for step in item["transformation_chain"]] == ["hex", "utf8"] for item in depth_two["recoveries"]))
        self.assertTrue(all(len(item["transformation_chain"]) <= 2 for item in depth_two["recoveries"]))

    def test_printable_and_cumulative_unique_output_budgets_are_enforced(self):
        exact, _ = self.analyze(b"test", max_output_bytes=4, max_depth=1)
        self.assertEqual(4, exact["metrics"]["output_bytes"])

        oversized, _ = self.analyze(b"hello", max_output_bytes=4, max_depth=1)
        self.assertEqual([], oversized["recoveries"])
        self.assertTrue(any(item["reason_code"] == "TOTAL_OUTPUT_BYTES" for item in oversized["failed_attempts"]))

        cumulative, _ = self.analyze(b"dGVzdA==", max_output_bytes=8, max_depth=1)
        self.assertLessEqual(cumulative["metrics"]["output_bytes"], 8)
        self.assertTrue(any(item["reason_code"] == "TOTAL_OUTPUT_BYTES" for item in cumulative["failed_attempts"]))

    def test_identical_bytes_from_distinct_chains_share_one_artifact(self):
        encoded = gzip.compress(b"hello", mtime=0)
        result, _ = self.analyze(encoded, max_output_bytes=5, max_depth=2)
        matching = [item for item in result["recoveries"] if item["output"]["sha256"] == hashlib.sha256(b"hello").hexdigest()]
        self.assertEqual(2, len(matching))
        self.assertEqual({("gzip",), ("gzip", "utf8")}, {tuple(step["operation"] for step in item["transformation_chain"]) for item in matching})
        self.assertEqual(1, len({item["output"]["artifact_ref"] for item in matching}))
        self.assertEqual(5, result["metrics"]["output_bytes"])

    def test_concatenated_gzip_members_are_recovered_completely(self):
        encoded = gzip.compress(b"first", mtime=0) + gzip.compress(b"second", mtime=0)
        result, output = self.analyze(encoded, max_output_bytes=11, max_depth=1)
        recovery = next(item for item in result["recoveries"] if [step["operation"] for step in item["transformation_chain"]] == ["gzip"])
        self.assertEqual(b"firstsecond", (output / recovery["output"]["artifact_ref"]).read_bytes())

    def test_gzip_and_zlib_trailing_data_are_rejected_atomically(self):
        for operation, encoded in (
            ("gzip", gzip.compress(b"first", mtime=0) + b"trailing"),
            ("zlib", zlib.compress(b"first") + b"trailing"),
        ):
            with self.subTest(operation=operation):
                result, _ = self.analyze(encoded, max_depth=1)
                self.assertFalse(any(step["operation"] == operation for item in result["recoveries"] for step in item["transformation_chain"]))
                self.assertTrue(any(item["operation"] == operation and item["reason_code"] == "TRAILING_DATA" for item in result["failed_attempts"]))

    def test_tls_metadata_without_key_is_explicitly_skipped(self):
        result, _ = self.analyze(b"opaque ciphertext", encrypted_protocol="tls")
        self.assertTrue(any(item["reason_code"] == "ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL" for item in result["skipped_sources"]))
        self.assertNotEqual("ok", result["status"])

    @staticmethod
    def record(content_type: int, payload: bytes) -> bytes:
        return bytes([content_type, 0x03, 0x03]) + len(payload).to_bytes(2, "big") + payload

    def test_declared_tls_plaintext_regions_are_recovered_and_ciphertext_refused(self):
        client_hello = bytes([0x01, 0x00, 0x00, 0x02]) + b"CH"
        server_hello = bytes([0x02, 0x00, 0x00, 0x02]) + b"SH"
        stream = (
            self.record(0x16, client_hello)     # [ 0, 11)  handshake, unprotected
            + self.record(0x16, server_hello)   # [11, 22)  handshake, unprotected
            + self.record(0x14, b"\x01")        # [22, 28)  dummy
            + self.record(0x17, b"\xaa" * 8)    # [28, 41)  protected
            + self.record(0x17, b"\xbb" * 6)    # [41, 52)  protected
        )
        result, output = self.analyze(stream, encrypted_protocol="tls")
        self.assertEqual("partial", result["status"])
        by_role = {item["transformation_chain"][0]["parameters"]["role"]: item for item in result["recoveries"]}
        self.assertEqual({"record_header", "handshake_plaintext", "change_cipher_spec"}, set(by_role))
        headers = by_role["record_header"]
        self.assertEqual("declared_plaintext_region", headers["transformation_chain"][0]["operation"])
        self.assertEqual("protocol_declared", headers["basis"])
        self.assertEqual("complete", headers["completeness"])
        self.assertEqual(25, headers["output"]["length"])
        self.assertEqual([{"start": 0, "end": 5}, {"start": 11, "end": 16}, {"start": 22, "end": 27},
                          {"start": 28, "end": 33}, {"start": 41, "end": 46}], headers["source_ranges"])
        handshake = by_role["handshake_plaintext"]
        self.assertEqual(client_hello + server_hello, (output / handshake["output"]["artifact_ref"]).read_bytes())
        self.assertEqual([{"start": 5, "end": 11}, {"start": 16, "end": 22}], handshake["source_ranges"])
        self.assertEqual([{"start": 27, "end": 28}], by_role["change_cipher_spec"]["source_ranges"])
        self.assertEqual(38, result["metrics"]["output_bytes"])
        self.assertEqual(1, len(result["skipped_sources"]))
        refused = result["skipped_sources"][0]
        self.assertEqual("DECLARED_PROTECTED_REGION", refused["reason_code"])
        self.assertEqual([{"start": 33, "end": 41}, {"start": 46, "end": 52}], refused["source_ranges"])

    def test_declared_layout_that_does_not_tile_the_input_keeps_the_refusal(self):
        result, output = self.analyze(self.record(0x17, b"\x01") + b"\x00\x00junk", encrypted_protocol="tls")
        self.assertEqual([], result["recoveries"])
        self.assertTrue(any(item["reason_code"] == "ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL" for item in result["skipped_sources"]))
        self.assertFalse(any(item["reason_code"] == "DECLARED_PROTECTED_REGION" for item in result["skipped_sources"]))
        self.assertFalse((output / "recovered").exists())

    def test_record_headers_stay_plaintext_when_every_payload_is_protected(self):
        stream = b"".join(self.record(0x17, bytes([index]) * 4) for index in range(3))
        result, _ = self.analyze(stream, encrypted_protocol="tls")
        roles = [item["transformation_chain"][0]["parameters"]["role"] for item in result["recoveries"]]
        self.assertEqual(["record_header"], roles)
        self.assertEqual(15, result["recoveries"][0]["output"]["length"])
        refused = result["skipped_sources"][0]
        self.assertEqual("DECLARED_PROTECTED_REGION", refused["reason_code"])
        self.assertEqual(3, len(refused["source_ranges"]))
        self.assertEqual(12, sum(region["end"] - region["start"] for region in refused["source_ranges"]))
        self.assertEqual(15, result["metrics"]["output_bytes"])

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

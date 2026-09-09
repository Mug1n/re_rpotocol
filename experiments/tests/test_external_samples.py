from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = ROOT / "data" / "external"
MANIFEST_PATH = EXTERNAL / "test-samples-manifest.json"
HEX_LINE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def load_m01():
    path = ROOT / "experiments" / "M01" / "run.py"
    spec = importlib.util.spec_from_file_location("external_samples_m01", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ExternalSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.m01 = load_m01()

    def test_manifest_files_match_frozen_size_and_hash(self):
        artifact_ids = []
        total_size = 0
        for dataset in self.manifest["datasets"]:
            for artifact in dataset["files"]:
                artifact_ids.append(artifact["artifact_id"])
                path = EXTERNAL / artifact["path"]
                self.assertTrue(path.is_file(), path)
                payload = path.read_bytes()
                total_size += len(payload)
                self.assertEqual(artifact["byte_size"], len(payload), path)
                self.assertEqual(artifact["sha256"], hashlib.sha256(payload).hexdigest(), path)
        self.assertEqual(len(artifact_ids), len(set(artifact_ids)))
        self.assertEqual(self.manifest["total_byte_size"], total_size)

    def test_capture_content_matches_declared_format_without_trusting_extension(self):
        for dataset in self.manifest["datasets"]:
            for artifact in dataset["files"]:
                expected = artifact.get("observed_format")
                if expected is None:
                    continue
                path = EXTERNAL / artifact["path"]
                self.assertEqual(expected, self.m01.probe_format(path).format, path)

    def test_binaryinferno_rows_are_decodable_hex_messages(self):
        dataset = next(
            item
            for item in self.manifest["datasets"]
            if item["dataset_id"] == "binaryinferno-ndss2023"
        )
        for artifact in dataset["files"]:
            path = EXTERNAL / artifact["path"]
            lines = [
                line.strip()
                for line in path.read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            self.assertEqual(artifact["message_count"], len(lines), path)
            self.assertTrue(all(HEX_LINE.fullmatch(line) for line in lines), path)
            self.assertEqual(
                artifact["decoded_byte_size"],
                sum(len(bytes.fromhex(line)) for line in lines),
                path,
            )


if __name__ == "__main__":
    unittest.main()

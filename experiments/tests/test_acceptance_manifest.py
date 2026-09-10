from __future__ import annotations

import hashlib
import json
import unittest
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FROZEN = ROOT / "data" / "acceptance" / "frozen-20260910"


class FrozenAcceptanceManifestTests(unittest.TestCase):
    def test_capture_hashes_truth_and_fixed_partitions(self) -> None:
        manifest = json.loads((FROZEN / "manifest.json").read_text(encoding="utf-8"))
        samples = manifest["samples"]
        self.assertEqual(18, len(samples))
        partitions: dict[str, Counter] = defaultdict(Counter)
        groups: dict[str, set[str]] = defaultdict(set)
        for sample in samples:
            capture = FROZEN / sample["input_path"]
            truth = FROZEN / sample["truth_path"]
            self.assertTrue(capture.is_file())
            self.assertTrue(truth.is_file())
            self.assertGreater(capture.stat().st_size, 0)
            self.assertEqual(sample["input_sha256"], hashlib.sha256(capture.read_bytes()).hexdigest())
            partitions[sample["action"]][sample["split"]] += 1
            groups[sample["group_id"]].add(sample["split"])
        self.assertEqual({"download", "upload", "periodic"}, set(partitions))
        for action in partitions:
            self.assertEqual(Counter({"train": 4, "validation": 1, "test": 1}), partitions[action])
        self.assertTrue(all(len(splits) == 1 for splits in groups.values()))

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M05" / "run.py"
SCHEMA_PATH = ROOT / "research" / "M05-alignment" / "alignment.schema.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m05_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_pairwise_alignment_preserves_byte_offsets_and_gap(self):
        result = self.module.needleman_wunsch(b"ABCD", b"ABXCD")
        self.assertEqual([(0, 0), (1, 1), (None, 2), (2, 3), (3, 4)], result["pairs"])
        self.assertEqual(4, result["matches"])
        self.assertEqual(1, result["gaps_in_reference"])
        self.assertEqual(0, result["gaps_in_target"])

    def test_reference_merge_creates_shared_columns_and_null_gaps(self):
        messages = {"ref": b"ABCD", "insert": b"ABXCD", "delete": b"ACD"}
        result = self.module.align_cluster(0, list(messages), "ref", messages)
        self.assertEqual(5, result["column_count"])
        insertion_columns = [column for column in result["columns"] if column["kind"] == "insertion"]
        self.assertEqual(1, len(insertion_columns))
        rows = {row["message_id"]: row for row in result["rows"]}
        self.assertIsNone(rows["ref"]["cells"][2])
        self.assertEqual([2, ord("X")], rows["insert"]["cells"][2])
        for message_id, data in messages.items():
            cells = [cell for cell in rows[message_id]["cells"] if cell is not None]
            self.assertEqual(list(range(len(data))), [cell[0] for cell in cells])
            self.assertEqual(list(data), [cell[1] for cell in cells])

    def test_pair_cell_safety_limit_and_scoring_validation(self):
        with self.assertRaises(ValueError):
            self.module.needleman_wunsch(b"1234", b"5678", max_pair_cells=20)
        with self.assertRaises(ValueError):
            self.module.needleman_wunsch(b"A", b"A", match_score=-1, mismatch_score=0)
        with self.assertRaises(ValueError):
            self.module.needleman_wunsch(b"A", b"A", gap_score=0)

    def test_empty_message_alignment_is_explicit(self):
        empty = self.module.needleman_wunsch(b"", b"")
        self.assertEqual([], empty["pairs"])
        self.assertEqual(0, empty["score"])
        self.assertIsNone(empty["identity_on_paired_bytes"])
        inserted = self.module.needleman_wunsch(b"", b"\x00")
        self.assertEqual([(None, 0)], inserted["pairs"])
        self.assertEqual(1, inserted["gaps_in_reference"])


class CliTests(unittest.TestCase):
    def test_cli_aligns_cluster_validates_schema_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_dir = root / "messages"
            message_dir.mkdir()
            payloads = {"ref": b"ABCD", "insert": b"ABXCD", "delete": b"ACD", "noise": b"ZZ"}
            framing_messages = []
            for message_id, data in payloads.items():
                artifact = message_dir / f"{message_id}.bin"
                artifact.write_bytes(data)
                framing_messages.append(
                    {"id": message_id, "length": len(data), "artifact_ref": f"messages/{message_id}.bin"}
                )
            framing = {"source": {"id": "fixture"}, "messages": framing_messages}
            framing_path = root / "framing.json"
            framing_path.write_text(json.dumps(framing), encoding="utf-8")
            framing_digest = hashlib.sha256(framing_path.read_bytes()).hexdigest()
            clusters = {
                "source": {
                    "framing_path": str(framing_path),
                    "framing_sha256": framing_digest,
                    "message_count": 4,
                },
                "assignments": [
                    {"message_id": "ref", "is_noise": False},
                    {"message_id": "insert", "is_noise": False},
                    {"message_id": "delete", "is_noise": False},
                    {"message_id": "noise", "is_noise": True},
                ],
                "clusters": [
                    {
                        "cluster_id": 0,
                        "message_ids": ["ref", "insert", "delete"],
                        "representative_message_id": "ref",
                    }
                ],
            }
            clusters_path = root / "clusters.json"
            clusters_path.write_text(json.dumps(clusters), encoding="utf-8")
            output = root / "output"
            command = [sys.executable, str(MODULE_PATH), str(clusters_path), "--output-dir", str(output)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads((output / "alignments.json").read_text(encoding="utf-8"))
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            jsonschema.validate(result, schema)
            self.assertEqual(3, result["metrics"]["aligned_message_count"])
            self.assertEqual([{"message_id": "noise", "reason": "m04_noise"}], result["unaligned_messages"])
            repeated = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(2, repeated.returncode)
            self.assertIn("already exists", repeated.stderr)

    def test_framing_hash_mismatch_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            framing_path = root / "framing.json"
            framing_path.write_text(json.dumps({"source": {}, "messages": []}), encoding="utf-8")
            clusters_path = root / "clusters.json"
            clusters_path.write_text(
                json.dumps(
                    {
                        "source": {"framing_path": str(framing_path), "framing_sha256": "0" * 64, "message_count": 0},
                        "assignments": [],
                        "clusters": [],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "output"
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), str(clusters_path), "--output-dir", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, completed.returncode)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

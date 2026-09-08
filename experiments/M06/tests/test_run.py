from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M06" / "run.py"
SCHEMA_PATH = ROOT / "research" / "M06-fields" / "format.schema.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m06_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_cluster() -> dict:
    payloads = [bytes([2, 0, 0, 0]) + b"AB", bytes([3, 0, 0, 0]) + b"ABC", bytes([4, 0, 0, 0]) + b"ABCD"]
    columns = [
        {
            "column_index": index,
            "kind": "reference",
            "reference_offset": index,
            "insertion_anchor": index,
            "insertion_ordinal": None,
        }
        for index in range(8)
    ]
    rows = []
    for index, payload in enumerate(payloads):
        cells = [[offset, value] for offset, value in enumerate(payload)]
        cells.extend([None] * (8 - len(cells)))
        rows.append({"message_id": f"m{index}", "length": len(payload), "cells": cells})
    return {
        "cluster_id": 0,
        "message_count": 3,
        "column_count": 8,
        "columns": columns,
        "rows": rows,
    }


class InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_column_statistics_distinguish_fixed_variable_and_optional(self):
        result = self.module.analyze_cluster(synthetic_cluster())
        columns = result["column_statistics"]
        self.assertEqual("variable", columns[0]["classification"])
        self.assertEqual("fixed", columns[1]["classification"])
        self.assertEqual("optional_fixed", columns[6]["classification"])
        self.assertEqual("sparse", columns[7]["classification"])
        self.assertEqual(1.0, columns[1]["most_common_ratio"])

    def test_little_endian_remaining_length_relation_is_found(self):
        result = self.module.analyze_cluster(synthetic_cluster())
        matches = [
            hypothesis
            for hypothesis in result["length_hypotheses"]
            if hypothesis["alignment_start"] == 0
            and hypothesis["width_bytes"] == 4
            and hypothesis["byteorder"] == "little"
            and hypothesis["relation"] == "remaining_bytes_after_field"
        ]
        self.assertEqual(1, len(matches))
        self.assertEqual([2, 3, 4], [item["decoded_value"] for item in matches[0]["observations"]])

    def test_constant_length_messages_do_not_create_length_hypotheses(self):
        cluster = synthetic_cluster()
        for row in cluster["rows"]:
            row["length"] = 8
            row["cells"] = [[index, index] for index in range(8)]
        result = self.module.analyze_cluster(cluster)
        self.assertEqual([], result["length_hypotheses"])

    def test_invalid_offset_mapping_is_rejected(self):
        cluster = synthetic_cluster()
        cluster["rows"][0]["cells"][1][0] = 7
        with self.assertRaises(ValueError):
            self.module.analyze_cluster(cluster)

    def test_small_cluster_is_marked_insufficient(self):
        cluster = synthetic_cluster()
        cluster["rows"] = cluster["rows"][:1]
        cluster["message_count"] = 1
        result = self.module.analyze_cluster(cluster, min_cluster_samples=2)
        self.assertTrue(
            all(column["classification"] == "insufficient_samples" for column in result["column_statistics"])
        )
        self.assertEqual([], result["length_hypotheses"])


class CliTests(unittest.TestCase):
    def test_cli_writes_schema_valid_output_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            alignments = {
                "source": {"stream_id": "fixture", "message_count": 3},
                "metrics": {"aligned_message_count": 3},
                "cluster_alignments": [synthetic_cluster()],
                "unaligned_messages": [],
            }
            source = root / "alignments.json"
            source.write_text(json.dumps(alignments), encoding="utf-8")
            output = root / "output"
            command = [sys.executable, str(MODULE_PATH), str(source), "--output-dir", str(output)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads((output / "format.json").read_text(encoding="utf-8"))
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            jsonschema.validate(result, schema)
            self.assertGreater(result["metrics"]["field_candidate_count"], 0)
            self.assertGreater(result["metrics"]["length_hypothesis_count"], 0)
            repeated = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(2, repeated.returncode)
            self.assertIn("already exists", repeated.stderr)


if __name__ == "__main__":
    unittest.main()

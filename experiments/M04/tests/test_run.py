from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M04" / "run.py"
SCHEMA_PATH = ROOT / "research" / "M04-clustering" / "clustering.schema.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m04_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_messages() -> list[tuple[str, bytes]]:
    return [
        ("a1", b"AA\x00\x00\x00\x01"),
        ("a2", b"AA\x00\x00\x00\x02"),
        ("a3", b"AA\x00\x00\x00\x03"),
        ("b1", b"BB\xff\xff\xff\x01"),
        ("b2", b"BB\xff\xff\xff\x02"),
        ("b3", b"BB\xff\xff\xff\x03"),
        ("noise", b"XYZ123456789"),
    ]


class ClusteringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def cluster(self):
        truth = {name: "A" if name.startswith("a") else "B" if name.startswith("b") else "noise" for name, _ in synthetic_messages()}
        return self.module.cluster_messages(
            synthetic_messages(),
            eps=0.18,
            min_samples=2,
            length_weight=0.1,
            histogram_weight=0.4,
            prefix_weight=0.5,
            prefix_length=4,
            truth_labels=truth,
        )

    def test_distance_is_symmetric_bounded_and_zero_for_identity(self):
        same, components = self.module.message_distance(b"ABC", b"ABC")
        forward, _ = self.module.message_distance(b"ABC", b"ABD")
        backward, _ = self.module.message_distance(b"ABD", b"ABC")
        self.assertEqual(0.0, same)
        self.assertTrue(all(value == 0.0 for value in components.values()))
        self.assertTrue(math.isclose(forward, backward, abs_tol=1e-12))
        self.assertGreaterEqual(forward, 0.0)
        self.assertLessEqual(forward, 1.0)

    def test_dbscan_recovers_two_groups_and_one_noise_message(self):
        result = self.cluster()
        assignments = {item["message_id"]: item for item in result["assignments"]}
        self.assertEqual(assignments["a1"]["cluster_id"], assignments["a3"]["cluster_id"])
        self.assertEqual(assignments["b1"]["cluster_id"], assignments["b3"]["cluster_id"])
        self.assertNotEqual(assignments["a1"]["cluster_id"], assignments["b1"]["cluster_id"])
        self.assertTrue(assignments["noise"]["is_noise"])
        self.assertEqual(2, result["metrics"]["cluster_count"])
        self.assertEqual(1, result["metrics"]["noise_count"])

    def test_external_metrics_are_perfect_for_exact_partition(self):
        result = self.cluster()
        self.assertTrue(math.isclose(1.0, result["metrics"]["adjusted_rand_index"], abs_tol=1e-12))
        self.assertTrue(math.isclose(1.0, result["metrics"]["normalized_mutual_information"], abs_tol=1e-12))
        self.assertGreater(result["metrics"]["silhouette"], 0.5)

    def test_nmi_constant_partition_ignores_label_names(self):
        self.assertEqual(
            1.0,
            self.module.normalized_mutual_information(["same"] * 4, [0] * 4),
        )
        self.assertEqual(
            0.0,
            self.module.normalized_mutual_information(["a", "a", "b", "b"], [0] * 4),
        )

    def test_representatives_are_real_messages(self):
        result = self.cluster()
        known = {name for name, _ in synthetic_messages()}
        for cluster in result["clusters"]:
            self.assertIn(cluster["representative_message_id"], known)
            self.assertIn(cluster["representative_message_id"], cluster["message_ids"])

    def test_safety_limit_rejects_large_input(self):
        with self.assertRaises(ValueError):
            self.module.cluster_messages(synthetic_messages(), max_messages=3)


class CliTests(unittest.TestCase):
    def test_cli_reads_m03_artifacts_validates_schema_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_dir = root / "messages"
            message_dir.mkdir()
            messages = synthetic_messages()
            framing_messages = []
            for index, (identifier, data) in enumerate(messages):
                path = message_dir / f"{identifier}.bin"
                path.write_bytes(data)
                framing_messages.append(
                    {"id": identifier, "length": len(data), "artifact_ref": f"messages/{identifier}.bin"}
                )
            framing = root / "framing.json"
            framing.write_text(
                json.dumps({"source": {"id": "synthetic"}, "messages": framing_messages}),
                encoding="utf-8",
            )
            output = root / "output"
            command = [
                sys.executable,
                str(MODULE_PATH),
                str(framing),
                "--output-dir",
                str(output),
                "--eps",
                "0.18",
                "--min-samples",
                "2",
                "--length-weight",
                "0.1",
                "--histogram-weight",
                "0.4",
                "--prefix-weight",
                "0.5",
                "--prefix-length",
                "4",
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, first.returncode, first.stderr)
            result = json.loads((output / "clusters.json").read_text(encoding="utf-8"))
            jsonschema.validate(result, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
            self.assertEqual(7, result["source"]["message_count"])
            self.assertEqual(2, result["metrics"]["cluster_count"])
            self.assertEqual(2, second.returncode)
            self.assertIn("already exists", second.stderr)


if __name__ == "__main__":
    unittest.main()

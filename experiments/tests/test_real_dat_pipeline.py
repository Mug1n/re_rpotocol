from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = ROOT / "data" / "external"
MANIFEST = EXTERNAL / "manifest.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class RealDatPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m01 = load_module("real_dat_m01", ROOT / "experiments" / "M01" / "run.py")
        cls.m02 = load_module("real_dat_m02", ROOT / "experiments" / "M02" / "run.py")
        cls.m03 = load_module("real_dat_m03", ROOT / "experiments" / "M03" / "run.py")
        cls.m04 = load_module("real_dat_m04", ROOT / "experiments" / "M04" / "run.py")
        cls.m05 = load_module("real_dat_m05", ROOT / "experiments" / "M05" / "run.py")
        cls.m06 = load_module("real_dat_m06", ROOT / "experiments" / "M06" / "run.py")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.artifacts = {item["artifact_id"]: item for item in manifest["artifacts"]}

    def data(self, artifact_id: str) -> tuple[Path, bytes, dict]:
        item = self.artifacts[artifact_id]
        path = EXTERNAL / item["path"]
        return path, path.read_bytes(), item

    def test_external_raw_files_match_manifest_and_are_not_capture_containers(self):
        for artifact_id in self.artifacts:
            with self.subTest(artifact_id=artifact_id):
                path, data, item = self.data(artifact_id)
                self.assertEqual(item["byte_size"], len(data))
                self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
                probe = self.m01.probe_format(path)
                self.assertEqual("raw_bytes", probe.format)

    def test_m02_real_dat_features_are_finite_and_normalized(self):
        for artifact_id in self.artifacts:
            with self.subTest(artifact_id=artifact_id):
                path, data, item = self.data(artifact_id)
                result = self.m02.analyze_bytes(
                    data,
                    source_id=artifact_id,
                    source_path=str(path),
                    source_sha256=item["sha256"],
                )
                features = result["global"]
                self.assertEqual(len(data), features["length"])
                self.assertTrue(math.isfinite(features["entropy_bits_per_byte"]))
                self.assertGreaterEqual(features["entropy_bits_per_byte"], 0.0)
                self.assertLessEqual(features["entropy_bits_per_byte"], 8.0)
                self.assertTrue(
                    math.isclose(1.0, sum(features["byte_frequencies"]), abs_tol=1e-12)
                )

    def test_audiobeat_fixed_channel_blocks_cover_every_byte(self):
        _, data, _ = self.data("audiobeat-dsp-m2-us002")
        messages, _, _ = self.m03.frame_fixed(
            data,
            stream_id="audiobeat",
            frame_size=238,
            start_offset=5,
        )
        self.assertEqual(10, len(messages))
        self.assertEqual((5, 243), (messages[0]["start"], messages[0]["end"]))
        self.assertEqual((2147, 2385), (messages[-1]["start"], messages[-1]["end"]))
        unparsed = self.m03._unparsed_ranges(len(data), messages)
        self.assertEqual([(0, 5), (2385, 2387)], [
            (item["start"], item["end"]) for item in unparsed
        ])
        self.assertEqual(len(data), sum(x["length"] for x in messages + unparsed))

    def test_watchpat_length_prefix_yields_fifteen_exact_records(self):
        _, data, _ = self.data("watchpat-testdata-15-packets")
        messages, diagnostics, _ = self.m03.frame_length_prefixed(
            data,
            stream_id="watchpat",
            length_offset=0,
            length_width=4,
            byteorder="little",
            length_mode="payload",
            header_size=4,
            max_frame_length=2048,
        )
        self.assertEqual(15, len(messages))
        self.assertTrue(all(item["accepted"] for item in diagnostics))
        self.assertEqual([], self.m03._unparsed_ranges(len(data), messages))
        self.assertEqual(len(data), sum(item["length"] for item in messages))

    def test_audiobeat_messages_have_complete_m04_assignments(self):
        _, data, _ = self.data("audiobeat-dsp-m2-us002")
        messages, _, _ = self.m03.frame_fixed(
            data,
            stream_id="audiobeat",
            frame_size=238,
            start_offset=5,
        )
        items = [
            (message["id"], data[message["start"]:message["end"]])
            for message in messages
        ]
        result = self.m04.cluster_messages(items, eps=0.11, min_samples=2)
        self.assertEqual(10, len(result["assignments"]))
        self.assertEqual(4, result["metrics"]["cluster_count"])
        self.assertEqual(0, result["metrics"]["noise_count"])
        self.assertEqual(
            10,
            sum(cluster["size"] for cluster in result["clusters"])
            + result["metrics"]["noise_count"],
        )

    def test_watchpat_messages_have_complete_m04_assignments(self):
        _, data, _ = self.data("watchpat-testdata-15-packets")
        messages, _, _ = self.m03.frame_length_prefixed(
            data,
            stream_id="watchpat",
            length_offset=0,
            length_width=4,
            byteorder="little",
            length_mode="payload",
            header_size=4,
            max_frame_length=2048,
        )
        items = [
            (message["id"], data[message["start"]:message["end"]])
            for message in messages
        ]
        result = self.m04.cluster_messages(items)
        self.assertEqual(15, len(result["assignments"]))
        self.assertEqual(1, result["metrics"]["cluster_count"])
        self.assertEqual(0, result["metrics"]["noise_count"])

    def assert_alignment_reconstructs_messages(self, alignment: dict, messages: dict[str, bytes]):
        for row in alignment["rows"]:
            cells = [cell for cell in row["cells"] if cell is not None]
            expected = messages[row["message_id"]]
            self.assertEqual(list(range(len(expected))), [cell[0] for cell in cells])
            self.assertEqual(list(expected), [cell[1] for cell in cells])

    def test_audiobeat_m05_alignment_preserves_all_clustered_bytes(self):
        _, data, _ = self.data("audiobeat-dsp-m2-us002")
        framed, _, _ = self.m03.frame_fixed(
            data, stream_id="audiobeat", frame_size=238, start_offset=5
        )
        messages = {
            item["id"]: data[item["start"]:item["end"]] for item in framed
        }
        clustered = self.m04.cluster_messages(list(messages.items()), eps=0.11)
        aligned_count = 0
        for cluster in clustered["clusters"]:
            alignment = self.m05.align_cluster(
                cluster["cluster_id"],
                cluster["message_ids"],
                cluster["representative_message_id"],
                messages,
            )
            self.assert_alignment_reconstructs_messages(alignment, messages)
            aligned_count += alignment["message_count"]
        self.assertEqual(10, aligned_count)

    def test_watchpat_m05_alignment_preserves_all_clustered_bytes(self):
        _, data, _ = self.data("watchpat-testdata-15-packets")
        framed, _, _ = self.m03.frame_length_prefixed(
            data,
            stream_id="watchpat",
            length_offset=0,
            length_width=4,
            byteorder="little",
            length_mode="payload",
            header_size=4,
            max_frame_length=2048,
        )
        messages = {
            item["id"]: data[item["start"]:item["end"]] for item in framed
        }
        clustered = self.m04.cluster_messages(list(messages.items()))
        cluster = clustered["clusters"][0]
        alignment = self.m05.align_cluster(
            cluster["cluster_id"],
            cluster["message_ids"],
            cluster["representative_message_id"],
            messages,
        )
        self.assert_alignment_reconstructs_messages(alignment, messages)
        self.assertEqual(15, alignment["message_count"])

    def test_audiobeat_m06_does_not_invent_length_relation_for_fixed_lengths(self):
        _, data, _ = self.data("audiobeat-dsp-m2-us002")
        framed, _, _ = self.m03.frame_fixed(
            data, stream_id="audiobeat", frame_size=238, start_offset=5
        )
        messages = {
            item["id"]: data[item["start"]:item["end"]] for item in framed
        }
        clustered = self.m04.cluster_messages(list(messages.items()), eps=0.11)
        for cluster in clustered["clusters"]:
            alignment = self.m05.align_cluster(
                cluster["cluster_id"], cluster["message_ids"],
                cluster["representative_message_id"], messages,
            )
            inferred = self.m06.analyze_cluster(alignment)
            self.assertEqual([], inferred["length_hypotheses"])

    def test_watchpat_m06_recovers_u32le_payload_length_relation(self):
        _, data, _ = self.data("watchpat-testdata-15-packets")
        framed, _, _ = self.m03.frame_length_prefixed(
            data, stream_id="watchpat", length_offset=0, length_width=4,
            byteorder="little", length_mode="payload", header_size=4,
            max_frame_length=2048,
        )
        messages = {
            item["id"]: data[item["start"]:item["end"]] for item in framed
        }
        clustered = self.m04.cluster_messages(list(messages.items()))
        cluster = clustered["clusters"][0]
        alignment = self.m05.align_cluster(
            cluster["cluster_id"], cluster["message_ids"],
            cluster["representative_message_id"], messages,
        )
        inferred = self.m06.analyze_cluster(alignment)
        matches = [
            item for item in inferred["length_hypotheses"]
            if item["alignment_start"] == 0
            and item["width_bytes"] == 4
            and item["byteorder"] == "little"
            and item["relation"] == "remaining_bytes_after_field"
        ]
        self.assertEqual(1, len(matches))
        self.assertEqual(15, matches[0]["sample_count"])


if __name__ == "__main__":
    unittest.main()

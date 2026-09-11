from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "experiments" / "M12" / "run.py"
EVIDENCE_SCHEMA = ROOT / "research" / "M12-llm" / "evidence.schema.json"
MANIFEST_SCHEMA = ROOT / "research" / "M12-llm" / "report-manifest.schema.json"
M01_FIXTURE = ROOT / "experiments" / "tests" / "fixtures" / "contracts" / "m01-complete.json"


def load_module():
    spec = importlib.util.spec_from_file_location("m12_run", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.m09 = cls._load_producer("m09_for_m12", ROOT / "experiments" / "M09" / "run.py")
        cls.m10 = cls._load_producer("m10_for_m12", ROOT / "experiments" / "M10" / "run.py")
        cls.m11 = cls._load_producer("m11_for_m12", ROOT / "experiments" / "M11" / "run.py")
        cls.evidence_schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        cls.manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

    @staticmethod
    def _load_producer(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def make_m01(self, root: Path) -> Path:
        source, digest = self.source_file(root, "capture.pcapng")
        artifact = json.loads(M01_FIXTURE.read_text(encoding="utf-8"))
        artifact["path"] = str(source)
        artifact["sha256"] = digest
        artifact["length"] = source.stat().st_size
        return self.write_artifact(root, "m01.json", artifact)

    def make_m07(self, root: Path, *, wrong_hash: bool = False, m01_path: Path | None = None) -> Path:
        m01_path = m01_path or self.make_m01(root)
        m01_hash = hashlib.sha256(m01_path.read_bytes()).hexdigest()
        artifact = {
            "schema_version": "0.1",
            "source": {"module": "M01", "artifact_path": str(m01_path), "artifact_sha256": "0" * 64 if wrong_hash else m01_hash, "record_id": "fixture-capture", "schema_version": "0.1"},
            "status": "ok", "parameters": {"decode_as": [], "display_filter": None, "timeout_seconds": 30, "max_capture_bytes": 1024, "max_observations": 500, "max_tshark_output_bytes": 4096},
            "tool": {"path": "fake", "version": "fake 1"},
            "observations": [{"observation_id": "obs-http", "scope_type": "packet", "scope_id": "packet-1", "protocol": "http", "recognition_mode": "dissector", "visibility": "application_visible", "field_evidence": [{"field": "http.request.method", "value": "GET"}], "limitations": []}],
            "unknown_scopes": [], "artifacts": [],
            "metrics": {"observation_count": 1, "unknown_scope_count": 0, "processed_record_count": 1, "truncated": False}, "warnings": []
        }
        path = root / ("m07-bad.json" if wrong_hash else "m07.json")
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def write_artifact(self, root: Path, name: str, value: dict) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def source_file(self, root: Path, name: str = "source.bin") -> tuple[Path, str]:
        path = root / name
        path.write_bytes(b"source evidence")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def make_m02(self, root: Path) -> Path:
        source, digest = self.source_file(root)
        summary = {
            "length": 15,
            "byte_counts": [0] * 256,
            "byte_frequencies": [0.0] * 256,
            "entropy_bits_per_byte": 2.5,
            "printable_ascii_ratio": 1.0,
            "ascii_whitespace_ratio": 0.0,
            "zero_ratio": 0.0,
        }
        artifact = {
            "schema_version": "0.1",
            "source": {"id": "source", "path": str(source), "sha256": digest, "range": {"start": 0, "end": 15}},
            "status": "ok",
            "parameters": {"entropy_log_base": 2, "printable_ascii_range": [32, 126], "ascii_whitespace_bytes": [9, 10, 13], "window_size": 256, "window_step": 256, "tail_window": "include_short_tail", "top_n": 8, "ngram_sizes": [2, 3, 4], "pattern_limit": 20, "pattern_offset_limit": 32, "ngram_counting": "overlapping"},
            "global": {**summary, "top_bytes": [], "prefix_preview_hex": "", "repeated_patterns": []},
            "windows": [],
            "warnings": ["Entropy alone cannot distinguish encryption, compression, and random data."],
        }
        return self.write_artifact(root, "m02.json", artifact)

    def digest(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_all_modules(self, root: Path) -> dict[str, Path]:
        raw, raw_hash = self.source_file(root, "capture.pcapng")
        m01 = self.make_m01(root)
        m02 = self.make_m02(root)
        m03 = self.write_artifact(root, "m03.json", {"schema_version": "0.1", "source": {"id": "s", "path": str(raw), "sha256": raw_hash, "length": raw.stat().st_size}, "status": "empty", "rule": "fixed", "parameters": {}, "messages": [], "unparsed_ranges": [], "diagnostics": [], "warnings": []})
        m04 = self.write_artifact(root, "m04.json", {"schema_version": "0.1", "source": {"framing_path": str(m03), "framing_sha256": self.digest(m03), "stream_id": None, "message_count": 0}, "status": "empty", "parameters": {}, "assignments": [], "clusters": [], "metrics": {"cluster_count": 0, "noise_count": 0, "noise_ratio": 0, "silhouette": None}, "warnings": []})
        m05 = self.write_artifact(root, "m05.json", {"schema_version": "0.1", "source": {"clusters_path": str(m04), "clusters_sha256": self.digest(m04), "framing_path": str(m03), "framing_sha256": self.digest(m03), "stream_id": None, "message_count": 0}, "status": "empty", "parameters": {"algorithm": "needleman_wunsch_reference", "match_score": 1, "mismatch_score": -1, "gap_score": -1, "max_pair_cells": 1}, "cluster_alignments": [], "unaligned_messages": [], "metrics": {"aligned_cluster_count": 0, "aligned_message_count": 0, "unaligned_message_count": 0, "total_alignment_columns": 0, "mean_identity_on_paired_bytes": None}, "warnings": []})
        m06 = self.write_artifact(root, "m06.json", {"schema_version": "0.1", "source": {"alignments_path": str(m05), "alignments_sha256": self.digest(m05), "stream_id": None, "message_count": 0, "aligned_message_count": 0}, "status": "empty", "parameters": {"method": "aligned_column_statistics", "min_cluster_samples": 1, "min_presence_ratio": 0.5, "length_widths": [1], "min_relation_samples": 1, "max_length_overhead": 0}, "cluster_formats": [], "unaligned_messages": [], "metrics": {"analyzed_cluster_count": 0, "analyzed_message_count": 0, "field_candidate_count": 0, "boundary_candidate_count": 0, "length_hypothesis_count": 0}, "warnings": []})
        m07 = self.make_m07(root, m01_path=m01)
        m08 = self.write_artifact(root, "m08.json", {"schema_version": "0.1", "source": {"module": "M01", "artifact_path": str(m01), "artifact_sha256": self.digest(m01), "record_id": "fixture-capture"}, "status": "no_recoverable_content", "parameters": {"max_input_bytes": 1024, "max_depth": 0, "max_output_bytes": 1024, "max_inflation_ratio": 10, "max_artifacts": 1, "min_printable_length": 1, "enabled_decoders": []}, "recoveries": [], "failed_attempts": [], "skipped_sources": [], "metrics": {"recovery_count": 0, "failed_attempt_count": 0, "skipped_source_count": 0, "output_bytes": 0}, "warnings": []})
        self.m09.analyze(m01, root / "m09-output")
        m09 = root / "m09-output" / "flow_features.json"
        self.m10.analyze(m09, root / "m10-output")
        m10 = root / "m10-output" / "behaviors.json"
        rows = self.write_artifact(root, "rows.json", {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": []})
        self.m11.analyze(rows, root / "m11-output", task="application")
        m11 = root / "m11-output" / "classification.json"
        return {f"M{index:02d}": path for index, path in enumerate((m01, m02, m03, m04, m05, m06, m07, m08, m09, m10, m11), 1)}

    def test_mixed_inputs_produce_stable_order_hashes_and_valid_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m01 = self.make_m01(root)
            m07 = self.make_m07(root, m01_path=m01)
            first = self.module.build_report({"M07": m07, "M01": m01}, root / "first")
            second = self.module.build_report({"M01": m01, "M07": m07}, root / "second")
            self.assertEqual((root / "first" / "report.md").read_bytes(), (root / "second" / "report.md").read_bytes())
            self.assertEqual(first["report_sha256"], second["report_sha256"])
            jsonschema.validate(first, self.manifest_schema)
            for item in json.loads((root / "first" / "evidence.json").read_text(encoding="utf-8")):
                jsonschema.validate(item, self.evidence_schema)
            self.assertEqual(["M01", "M07"], [item["module"] for item in first["inputs"]])

    def test_missing_modules_create_partial_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.module.build_report({"M01": self.make_m01(root)}, root / "out")
            report = (root / "out" / "report.md").read_text(encoding="utf-8")
            self.assertEqual("partial", manifest["status"])
            self.assertIn("无法判断", report)
            self.assertIn("M07", report)

    def test_tampered_upstream_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                self.module.build_report({"M07": self.make_m07(root, wrong_hash=True)}, output)
            self.assertFalse(output.exists())

    def test_evidence_limit_is_deterministic_and_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m01 = self.make_m01(root)
            manifest = self.module.build_report({"M01": m01, "M07": self.make_m07(root, m01_path=m01)}, root / "out", max_evidence=1)
            self.assertEqual(1, manifest["truncation"]["included"])
            self.assertGreater(manifest["truncation"]["omitted"], 0)

    def test_model_adapter_is_never_called_for_this_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            called = threading.Event()
            manifest = self.module.build_report({"M01": self.make_m01(root)}, root / "out", model_adapter=lambda evidence: called.set())
            self.assertFalse(called.is_set())
            self.assertEqual("deterministic", manifest["generation_mode"])
            self.assertEqual([], manifest["sections"]["interpretations"])
            self.assertIn("disabled", " ".join(manifest["warnings"]).lower())

    def test_m02_schema_and_adapter_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.module.build_report({"M02": self.make_m02(root)}, root / "out")
            evidence = json.loads((root / "out" / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual("M02", evidence[0]["module"])
            self.assertIn("entropy", evidence[0]["observation"].lower())
            self.assertEqual("partial", manifest["status"])

    def test_m02_schema_matches_the_producer_output(self):
        spec = importlib.util.spec_from_file_location("m02_for_m12_test", ROOT / "experiments" / "M02" / "run.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        artifact = producer.analyze_bytes(b"ABAB", source_id="fixture", source_path="fixture.bin", source_sha256="0" * 64)
        schema = json.loads((ROOT / "research" / "M02-features" / "features.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(artifact, schema)

    def test_all_m01_through_m11_inputs_reach_complete_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.module.build_report(self.make_all_modules(root), root / "out")
            self.assertEqual("complete", manifest["status"])
            self.assertEqual([], sorted(set(self.module.EXPECTED_MODULES) - {item["module"] for item in manifest["inputs"]}))

    def test_m07_scope_must_exist_in_referenced_m01(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = json.loads(self.make_m07(root).read_text(encoding="utf-8"))
            artifact["observations"][0]["scope_id"] = "missing-packet"
            bad = self.write_artifact(root, "bad-scope.json", artifact)
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "unknown M01 packet scope"):
                self.module.build_report({"M07": bad}, output)
            self.assertFalse(output.exists())

    def test_m07_unknown_input_scope_must_match_referenced_m01(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = json.loads(self.make_m07(root).read_text(encoding="utf-8"))
            artifact["observations"] = []
            artifact["unknown_scopes"] = [{"scope_type": "input", "scope_id": "different-input", "reason_code": "NO_MATCH"}]
            artifact["metrics"].update({"observation_count": 0, "unknown_scope_count": 1})
            bad = self.write_artifact(root, "bad-input-scope.json", artifact)
            with self.assertRaisesRegex(ValueError, "unknown M01 input scope"):
                self.module.build_report({"M07": bad}, root / "out")

    def test_m09_m10_m11_use_record_level_adapters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m01 = self.make_m01(root)
            self.m09.analyze(m01, root / "m09-output")
            m09 = root / "m09-output" / "flow_features.json"
            self.m10.analyze(m09, root / "m10-output", burst_packets=1)
            m10 = root / "m10-output" / "behaviors.json"
            rows = []
            for index in range(12):
                label = "alpha" if index % 2 else "beta"
                rows.append({"id": f"flow-{index}", "group_id": f"g{index}", "labels": {"application": label}, "features": {"bytes": 100 if label == "alpha" else 1, "packets": 10 if label == "alpha" else 1}})
            row_path = self.write_artifact(root, "rows.json", {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": rows})
            self.m11.analyze(row_path, root / "m11-output", task="application")
            m11 = root / "m11-output" / "classification.json"
            self.module.build_report({"M09": m09, "M10": m10, "M11": m11}, root / "out")
            evidence = json.loads((root / "out" / "evidence.json").read_text(encoding="utf-8"))
            observations = lambda module: [item["observation"] for item in evidence if item["module"] == module]
            self.assertTrue(any("64 bytes" in item for item in observations("M09")))
            self.assertTrue(any("bursty_transfer" in item for item in observations("M10")))
            self.assertTrue(any("alpha" in item for item in observations("M11")))

    def test_m03_through_m06_use_record_level_adapters(self):
        fixtures = {
            "M03": {
                "messages": [{"id": "message-1", "start": 0, "end": 4, "length": 4}],
                "unparsed_ranges": [], "rule": "fixed", "warnings": [],
            },
            "M04": {
                "clusters": [{"cluster_id": 2, "size": 3,
                              "representative_message_id": "message-1",
                              "mean_distance_to_representative": 0.1}],
                "assignments": [], "warnings": [],
            },
            "M05": {
                "cluster_alignments": [{"cluster_id": 2, "message_count": 3,
                                        "reference_length": 4, "column_count": 5,
                                        "rows": [{"identity_on_paired_bytes": 0.75}]}],
                "unaligned_messages": [], "warnings": [],
            },
            "M06": {
                "cluster_formats": [{
                    "cluster_id": 2,
                    "field_candidates": [{"field_id": "field-0001", "alignment_start": 0,
                                          "alignment_end": 1, "classification": "fixed",
                                          "width_columns": 2, "mean_entropy_bits": 0.0}],
                    "boundary_candidates": [{"alignment_column": 2,
                                             "left_field_id": "field-0001",
                                             "right_field_id": "field-0002",
                                             "reasons": ["column_class_change"]}],
                    "length_hypotheses": [{"hypothesis_id": "length-0001",
                                           "width_bytes": 2, "byteorder": "little",
                                           "relation": "message_length", "sample_count": 3,
                                           "exact_match_ratio": 1.0}],
                }],
                "warnings": [],
            },
        }
        expected_terms = {"M03": "Message message-1", "M04": "Cluster 2",
                          "M05": "alignment", "M06": "field field-0001"}
        for module, artifact in fixtures.items():
            with self.subTest(module=module):
                context = {"module": module, "path": Path(f"{module}.json"),
                           "artifact_sha256": "0" * 64, "schema_version": "0.1"}
                evidence = list(self.module._normalize(context, artifact))
                self.assertTrue(evidence)
                self.assertIn(expected_terms[module], evidence[0]["observation"])
                self.assertNotIn("artifact status=", evidence[0]["observation"])
                for item in evidence:
                    jsonschema.validate(item, self.evidence_schema)

    def test_m11_model_artifact_is_hash_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rows = []
            for index in range(12):
                label = "alpha" if index % 2 else "beta"
                rows.append({
                    "id": str(index), "group_id": f"g{index}",
                    "labels": {"application": label},
                    "features": {"bytes": 100 if label == "alpha" else 1},
                })
            source = self.write_artifact(
                root, "rows.json",
                {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": rows},
            )
            m11_dir = root / "m11"
            self.m11.analyze(source, m11_dir, task="application")
            (m11_dir / "model.joblib").write_bytes(b"tampered")
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "model artifact (length|SHA-256) mismatch"):
                self.module.build_report({"M11": m11_dir / "classification.json"}, output)
            self.assertFalse(output.exists())

    def test_input_size_is_checked_before_json_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "large.json"
            artifact.write_bytes(b"{" + b" " * 32)
            with self.assertRaisesRegex(ValueError, "exceeds max_input_bytes"):
                self.module.build_report({"M01": artifact}, root / "out", max_input_bytes=16)

    def test_many_observations_respect_bound_during_normalization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = json.loads(self.make_m07(root).read_text(encoding="utf-8"))
            artifact["observations"] = [{**artifact["observations"][0], "observation_id": f"obs-{index}"} for index in range(100)]
            artifact["metrics"]["observation_count"] = 100
            path = self.write_artifact(root, "many.json", artifact)
            manifest = self.module.build_report({"M07": path}, root / "out", max_evidence=1)
            self.assertEqual({"limit": 1, "included": 1, "omitted": 99}, manifest["truncation"])

    def test_legacy_source_layouts_are_hash_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, digest = self.source_file(root)
            cases = {
                "M03": {"source": {"id": "s", "path": str(source), "sha256": digest, "length": source.stat().st_size}, "status": "empty", "rule": "fixed", "parameters": {}, "messages": [], "unparsed_ranges": [], "diagnostics": [], "warnings": []},
                "M04": {"source": {"framing_path": str(source), "framing_sha256": digest, "stream_id": None, "message_count": 0}, "status": "empty", "parameters": {}, "assignments": [], "clusters": [], "metrics": {"cluster_count": 0, "noise_count": 0, "noise_ratio": 0, "silhouette": None}, "warnings": []},
                "M05": {"source": {"clusters_path": str(source), "clusters_sha256": digest, "framing_path": str(source), "framing_sha256": digest, "stream_id": None, "message_count": 0}, "status": "empty", "parameters": {"algorithm": "needleman_wunsch_reference", "match_score": 1, "mismatch_score": -1, "gap_score": -1, "max_pair_cells": 1}, "cluster_alignments": [], "unaligned_messages": [], "metrics": {"aligned_cluster_count": 0, "aligned_message_count": 0, "unaligned_message_count": 0, "total_alignment_columns": 0, "mean_identity_on_paired_bytes": None}, "warnings": []},
                "M06": {"source": {"alignments_path": str(source), "alignments_sha256": digest, "stream_id": None, "message_count": 0, "aligned_message_count": 0}, "status": "empty", "parameters": {"method": "aligned_column_statistics", "min_cluster_samples": 1, "min_presence_ratio": 0.5, "length_widths": [1], "min_relation_samples": 1, "max_length_overhead": 0}, "cluster_formats": [], "unaligned_messages": [], "metrics": {"analyzed_cluster_count": 0, "analyzed_message_count": 0, "field_candidate_count": 0, "boundary_candidate_count": 0, "length_hypothesis_count": 0}, "warnings": []},
            }
            for module, value in cases.items():
                value["schema_version"] = "0.1"
                path = self.write_artifact(root, f"{module}.json", value)
                source.write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    self.module.build_report({module: path}, root / f"out-{module}")
                source.write_bytes(b"source evidence")

    def test_multiple_artifacts_for_one_module_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts = self.make_all_modules(root)
            second = root / "m08-second.json"
            second.write_bytes(artifacts["M08"].read_bytes())
            manifest = self.module.build_report(
                {"M08": [artifacts["M08"], second]}, root / "multi-m08"
            )
            self.assertEqual(2, len(manifest["inputs"]))
            self.assertEqual({str(artifacts["M08"]), str(second)}, {
                item["artifact_path"] for item in manifest["inputs"]
            })
            with self.assertRaisesRegex(ValueError, "duplicate module artifact path"):
                self.module.build_report(
                    {"M08": [artifacts["M08"], artifacts["M08"]]},
                    root / "duplicate-m08",
                )

    def test_m01_m02_and_canonical_m08_m11_source_refs_are_hash_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts = self.make_all_modules(root)
            cases = {
                "M01": Path(json.loads(artifacts["M01"].read_text(encoding="utf-8"))["path"]),
                "M02": Path(json.loads(artifacts["M02"].read_text(encoding="utf-8"))["source"]["path"]),
                "M08": artifacts["M01"],
                "M09": artifacts["M01"],
                "M10": artifacts["M09"],
                "M11": root / "rows.json",
            }
            for module, source in cases.items():
                with self.subTest(module=module):
                    original = source.read_bytes()
                    source.write_bytes(original + b"tampered")
                    with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        self.module.build_report({module: artifacts[module]}, root / f"tampered-{module}")
                    source.write_bytes(original)


if __name__ == "__main__":
    unittest.main()

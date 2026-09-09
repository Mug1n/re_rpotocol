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
        cls.evidence_schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        cls.manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

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
        m09 = self.write_artifact(root, "m09.json", {"schema_version": "0.1", "source": {"module": "M01", "artifact_path": str(m01), "artifact_sha256": self.digest(m01), "record_count": 0}, "status": "empty", "parameters": {}, "feature_definition": {}, "metrics": {}, "flows": [], "unavailable_features": [], "warnings": []})
        m10 = self.write_artifact(root, "m10.json", {"schema_version": "0.1", "source": {"module": "M09", "artifact_path": str(m09), "artifact_sha256": self.digest(m09), "record_count": 0}, "status": "empty", "parameters": {}, "rule_set": {}, "metrics": {}, "observations": [], "insufficient_scopes": [], "warnings": []})
        rows = self.write_artifact(root, "rows.json", {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": []})
        m11 = self.write_artifact(root, "m11.json", {"schema_version": "0.1", "source": {"module": "M09-compatible-feature-rows", "artifact_path": str(rows), "artifact_sha256": self.digest(rows), "record_count": 0}, "status": "empty", "parameters": {}, "task": {"label_dimension": "application", "classes": [], "unknown_rejection": "not implemented", "feature_schema_version": "0.1"}, "split": {"group_key": "group_id", "train_count": 0, "test_count": 0, "group_overlap": [], "random_seed": 17}, "model": None, "metrics": None, "predictions": [], "leakage_checks": {}, "warnings": []})
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
            upstream, upstream_hash = self.source_file(root, "upstream.json")
            source = {"module": "M01", "artifact_path": str(upstream), "artifact_sha256": upstream_hash, "record_count": 1}
            m09 = self.write_artifact(root, "m09.json", {"schema_version": "0.1", "source": source, "status": "ok", "parameters": {}, "feature_definition": {}, "metrics": {}, "flows": [{"flow_id": "flow-1", "packet_count": 2, "byte_count": 42, "directional": {}, "packet_length": {}, "duration_seconds": 1.5, "integrity": {}}], "unavailable_features": [], "warnings": []})
            source10 = {"module": "M09", "artifact_path": str(m09), "artifact_sha256": hashlib.sha256(m09.read_bytes()).hexdigest(), "record_count": 1}
            m10 = self.write_artifact(root, "m10.json", {"schema_version": "0.1", "source": source10, "status": "ok", "parameters": {}, "rule_set": {}, "metrics": {}, "observations": [{"behavior_id": "b1", "flow_id": "flow-1", "type": "bursty_transfer", "observed_values": {"max_burst_packets": 4}, "thresholds": {"min_burst_packets": 3}, "evidence_refs": [], "limitations": ["pattern only"]}], "insufficient_scopes": [], "warnings": []})
            source11 = {"module": "M09-compatible-feature-rows", "artifact_path": str(upstream), "artifact_sha256": upstream_hash, "record_count": 1}
            m11 = self.write_artifact(root, "m11.json", {"schema_version": "0.1", "source": source11, "status": "evaluation_only", "parameters": {}, "task": {"label_dimension": "application", "classes": ["alpha"], "unknown_rejection": "enabled", "feature_schema_version": "0.1"}, "split": {"group_key": "group_id", "train_count": 1, "test_count": 1, "group_overlap": [], "random_seed": 17}, "model": {}, "metrics": {}, "predictions": [{"scope_id": "flow-1", "predicted_label": "alpha", "score_type": "class_probability", "score": 0.75, "rejected": False}], "leakage_checks": {}, "warnings": []})
            self.module.build_report({"M09": m09, "M10": m10, "M11": m11}, root / "out")
            evidence = json.loads((root / "out" / "evidence.json").read_text(encoding="utf-8"))
            by_module = {item["module"]: item for item in evidence}
            self.assertIn("42 bytes", by_module["M09"]["observation"])
            self.assertIn("bursty_transfer", by_module["M10"]["observation"])
            self.assertIn("alpha", by_module["M11"]["observation"])

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

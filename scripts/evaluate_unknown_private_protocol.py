#!/usr/bin/env python3
"""Evaluate held-out private-protocol traffic without exposing truth to analysis."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.M03.run import evaluate_framing
from experiments.M04.run import adjusted_rand_index, normalized_mutual_information
from scripts.analyze import run_pipeline


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_truth(path: Path, source: Path) -> dict[str, Any]:
    truth = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "research" / "unknown-protocol-truth.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(truth, schema)
    if truth["input_sha256"] != sha256(source):
        raise ValueError("truth input_sha256 does not bind to the supplied held-out input")
    previous = 0
    for message in truth["messages"]:
        if message["start"] < previous or message["end"] <= message["start"] or message["end"] > source.stat().st_size:
            raise ValueError("truth messages overlap or exceed the held-out input")
        previous = message["end"]
        for field in message["fields"]:
            if not message["start"] <= field["start"] < field["end"] <= message["end"]:
                raise ValueError("truth field lies outside its message")
    return truth


def _field_boundaries(truth: dict[str, Any]) -> set[tuple[int, int]]:
    boundaries: set[tuple[int, int]] = set()
    for message in truth["messages"]:
        for field in message["fields"]:
            for value in (field["start"], field["end"]):
                if value not in (message["start"], message["end"]):
                    boundaries.add((message["start"], value))
    return boundaries


def evaluate(source: Path, truth_path: Path, profile: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    truth = load_truth(truth_path, source)
    # The truth object is intentionally not supplied to run_pipeline.
    manifest = run_pipeline(source, output, profile)
    framing = json.loads((output / "m03" / "framing.json").read_text(encoding="utf-8"))
    clusters = json.loads((output / "m04" / "clusters.json").read_text(encoding="utf-8"))
    formats = json.loads((output / "m06" / "format.json").read_text(encoding="utf-8"))
    expected = [(item["start"], item["end"]) for item in truth["messages"]]
    predicted = [(item["start"], item["end"]) for item in framing["messages"]]
    boundary = evaluate_framing(predicted, expected, stream_length=source.stat().st_size)
    truth_by_range = {(item["start"], item["end"]): item for item in truth["messages"]}
    assignments = {item["message_id"]: str(item["cluster_id"]) for item in clusters.get("assignments", [])}
    type_truth, type_predicted = [], []
    for message in framing["messages"]:
        item = truth_by_range.get((message["start"], message["end"]))
        if item and message["id"] in assignments:
            type_truth.append(item["type"])
            type_predicted.append(assignments[message["id"]])
    type_metrics = {"scored_message_count": len(type_truth), "ari": None, "nmi": None}
    if len(type_truth) >= 2:
        type_metrics.update({"ari": adjusted_rand_index(type_truth, type_predicted),
                             "nmi": normalized_mutual_information(type_truth, type_predicted)})
    candidate_boundaries: set[tuple[int, int]] = set()
    for cluster in formats.get("cluster_formats", []):
        for candidate in cluster.get("field_candidates", []):
            for key in ("reference_offset_start", "reference_offset_end"):
                value = candidate.get(key)
                if value is not None:
                    for message in framing["messages"]:
                        if assignments.get(message["id"]) == str(cluster.get("cluster_id")) and 0 < value < message["length"]:
                            candidate_boundaries.add((message["start"], message["start"] + value))
    expected_fields = _field_boundaries(truth)
    matched = len(candidate_boundaries & expected_fields)
    field_metrics = {"candidate_count": len(candidate_boundaries), "truth_boundary_count": len(expected_fields),
                     "matched": matched,
                     "precision": matched / len(candidate_boundaries) if candidate_boundaries else 0.0,
                     "recall": matched / len(expected_fields) if expected_fields else 1.0}
    report = {
        "schema_version": "0.1", "status": manifest["status"], "corpus_id": truth["corpus_id"],
        "truth_used_after_analysis": True, "input_sha256": sha256(source),
        "boundary_metrics": boundary, "type_metrics": type_metrics, "field_metrics": field_metrics,
        "ambiguity": {"framing_candidate_count": framing.get("parameters", {}).get("candidate_count", 0),
                      "unparsed_ranges": framing.get("unparsed_ranges", []),
                      "m04_noise_count": clusters.get("metrics", {}).get("noise_count", 0)},
        "limitations": ["Truth is loaded only after run_pipeline completes.", "Cluster IDs are compared as partitions, using ARI/NMI rather than their numeric names.", "Field scores measure candidate internal boundaries; they do not prove field semantics."],
    }
    (output / "held_out_evaluation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Score held-out private protocol traffic after label-free analysis.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        evaluate(args.input, args.truth, args.profile, args.output_dir)
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        print(f"held-out-evaluation: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "held_out_evaluation.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

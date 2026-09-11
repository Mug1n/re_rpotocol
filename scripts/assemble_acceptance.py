#!/usr/bin/env python3
"""Assemble A's run with independent truth, classifier, and persisted model evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = ROOT / "research" / "run-manifest.schema.json"
ACCEPTANCE_SCHEMA = ROOT / "research" / "acceptance.schema.json"
EXPECTED_MODULES = {f"M{index:02d}" for index in range(1, 12)}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def record(path: Path, **extra: Any) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return {"path": str(path), "sha256": sha256(path), "length": path.stat().st_size, **extra}


def assemble(run_path: Path, truth_path: Path, evaluation_path: Path,
             model_manifest_path: Path, output_path: Path) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(output_path)
    run = load(run_path)
    jsonschema.validate(run, load(RUN_SCHEMA))
    if run["status"] != "complete":
        raise ValueError("analysis run is not complete")
    by_module: dict[str, list[dict[str, Any]]] = {}
    for item in run["artifacts"]:
        by_module.setdefault(item["module"], []).append(item)
        path = Path(item["path"])
        if not path.is_file() or path.stat().st_size != item["length"] or sha256(path) != item["sha256"]:
            raise ValueError(f"run artifact hash mismatch: {path}")

    m12_records = by_module.get("M12", [])
    if len(m12_records) != 1:
        raise ValueError("run must contain exactly one M12 report manifest")
    m12_path = Path(m12_records[0]["path"])
    m12 = load(m12_path)
    inputs: dict[str, dict[str, Any]] = {}
    for item in m12.get("inputs", []):
        module, path = item["module"], Path(item["artifact_path"])
        if module in inputs:
            raise ValueError("final acceptance currently requires one artifact per M01-M11 module")
        inputs[module] = record(path, schema_version=item["schema_version"], status=item["status"])
        if inputs[module]["sha256"] != item["artifact_sha256"]:
            raise ValueError(f"M12 input hash mismatch: {module}")
    if set(inputs) != EXPECTED_MODULES or m12.get("status") != "complete":
        raise ValueError("M12 does not contain complete M01-M11 coverage")

    truth = load(truth_path)
    expected = truth.get("response_sha256")
    if not isinstance(expected, str):
        raise ValueError("truth has no response_sha256")
    matches = []
    for artifact in by_module.get("M08", []):
        recovery_path = Path(artifact["path"])
        recovery = load(recovery_path)
        for item in recovery.get("recoveries", []):
            candidate = recovery_path.parent / item.get("output", {}).get("artifact_ref", "")
            if (item.get("completeness") == "complete" and candidate.is_file()
                    and item.get("output", {}).get("sha256") == expected and sha256(candidate) == expected):
                matches.append((item, candidate))
    if len(matches) != 1:
        raise ValueError("expected exactly one complete recovery matching independent truth")
    recovery_item, recovered_path = matches[0]

    prediction_records = by_module.get("M11_PREDICTION", [])
    if len(prediction_records) != 1:
        raise ValueError("run must contain one label-free M11 prediction")
    prediction_path = Path(prediction_records[0]["path"])
    prediction = load(prediction_path)
    if not prediction.get("predictions"):
        raise ValueError("prediction artifact is empty")
    evaluation = load(evaluation_path)
    model_path = evaluation_path.parent / evaluation.get("model", {}).get("artifact_ref", "")
    if not model_path.is_file() or sha256(model_path) != evaluation.get("model", {}).get("sha256"):
        raise ValueError("classifier evaluation does not bind its model")
    if prediction.get("model", {}).get("sha256") != sha256(model_path):
        raise ValueError("prediction does not bind the evaluated classifier")

    model = load(model_manifest_path)
    if model.get("status") != "invoked":
        raise ValueError("persisted semantic model was not invoked")
    for key in ("request", "response"):
        path = Path(model.get(key, {}).get("path", ""))
        if not path.is_file() or sha256(path) != model[key].get("sha256"):
            raise ValueError(f"semantic model {key} hash mismatch")

    result = {
        "schema_version": "0.1", "status": "complete", "input": inputs,
        "deterministic_report": {"manifest": record(m12_path), "status": m12["status"],
                                 "generation_mode": m12["generation_mode"]},
        "recovery": {"status": "matched", "recovery_id": recovery_item["recovery_id"],
                     "expected_sha256": expected, "recovered": record(recovered_path),
                     "truth": record(truth_path)},
        "classification": {"evaluation": record(evaluation_path), "prediction": record(prediction_path),
                           "model": record(model_path),
                           "test_macro_f1": evaluation.get("test", {}).get("macro_f1"),
                           "validation_macro_f1": evaluation.get("validation", {}).get("macro_f1")},
        "model": {**model, "manifest": record(model_manifest_path)},
        "limitations": list(run.get("limitations", [])) + [
            "The persisted model call is replayed and hash-verified; this assembly does not make a second paid API call.",
            "Classifier metrics come from a small controlled loopback capture set and are not a broad generalization claim.",
        ],
    }
    jsonschema.validate(result, load(ACCEPTANCE_SCHEMA))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble a complete acceptance record from separately governed evidence.")
    parser.add_argument("--run-manifest", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--classifier-evaluation", required=True, type=Path)
    parser.add_argument("--model-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        assemble(args.run_manifest, args.truth, args.classifier_evaluation, args.model_manifest, args.output)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        print(f"assemble-acceptance: {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

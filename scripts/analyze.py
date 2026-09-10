#!/usr/bin/env python3
"""Build a hash-bound acceptance run manifest from actual module outputs.

This is an integration boundary, not a substitute for an unavailable language
model.  It records the model state explicitly and only calls M12's deterministic
evidence renderer for artifacts whose published contracts it can validate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.M12.run import build_report


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return {"path": str(path), "sha256": sha256(path), "length": path.stat().st_size}


def validate_recovery(recovery_path: Path, truth_path: Path) -> dict[str, Any]:
    recovery, truth = load(recovery_path), load(truth_path)
    if recovery.get("status") not in {"ok", "partial"}:
        raise ValueError("recovery did not report a usable status")
    expected = truth.get("response_sha256")
    if not isinstance(expected, str):
        raise ValueError("truth has no independent response_sha256")
    for item in recovery.get("recoveries", []):
        output = item.get("output", {})
        candidate = recovery_path.parent / str(output.get("artifact_ref", ""))
        if (item.get("completeness") == "complete" and candidate.is_file()
                and output.get("sha256") == expected and sha256(candidate) == expected):
            return {"status": "matched", "recovery_id": item["recovery_id"], "expected_sha256": expected,
                    "recovered": record(candidate), "truth": record(truth_path)}
    raise ValueError("no complete recovered output matches the independent truth SHA-256")


def validate_classifier(evaluation_path: Path, prediction_path: Path) -> dict[str, Any]:
    evaluation, prediction = load(evaluation_path), load(prediction_path)
    model = evaluation.get("model", {})
    model_path = evaluation_path.parent / str(model.get("artifact_ref", ""))
    if not model_path.is_file() or sha256(model_path) != model.get("sha256"):
        raise ValueError("classifier model hash validation failed")
    if prediction.get("status") != "ok" or prediction.get("model", {}).get("sha256") != model.get("sha256"):
        raise ValueError("prediction artifact is not bound to the evaluated model")
    if not prediction.get("predictions"):
        raise ValueError("prediction artifact is empty")
    return {"evaluation": record(evaluation_path), "prediction": record(prediction_path), "model": record(model_path),
            "test_macro_f1": evaluation.get("test", {}).get("macro_f1"),
            "validation_macro_f1": evaluation.get("validation", {}).get("macro_f1")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a real, hash-bound acceptance integration manifest.")
    parser.add_argument("--m01", required=True, type=Path)
    parser.add_argument("--m09", required=True, type=Path)
    parser.add_argument("--recovery", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--classifier-evaluation", required=True, type=Path)
    parser.add_argument("--classifier-prediction", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--local-model-id", help="Recorded only after a separately verified local model invocation.")
    args = parser.parse_args(argv)
    if args.output_dir.exists():
        raise FileExistsError(f"output directory exists: {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    try:
        # M12 validates M01 and M09 source hashes before producing deterministic evidence.
        m12 = build_report({"M01": args.m01, "M09": args.m09}, args.output_dir / "m12")
        recovery = validate_recovery(args.recovery, args.truth)
        classifier = validate_classifier(args.classifier_evaluation, args.classifier_prediction)
        model = ({"status": "not_invoked", "id": args.local_model_id,
                  "reason": "Adapter invocation is deliberately disabled until a bounded semantic validator is supplied."}
                 if args.local_model_id else
                 {"status": "blocked", "reason": "No local model executable or endpoint was found on this host."})
        manifest = {
            "schema_version": "0.1", "status": "partial", "input": {"m01": record(args.m01), "m09": record(args.m09)},
            "deterministic_report": {"manifest": record(args.output_dir / "m12" / "report_manifest.json"),
                                     "status": m12["status"], "generation_mode": m12["generation_mode"]},
            "recovery": recovery, "classification": classifier, "model": model,
            "limitations": ["The classifier was assessed on a small self-controlled frozen batch.",
                            "No semantic model claim is emitted without a verified local model invocation and bounded validator."],
        }
        (args.output_dir / "run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        shutil.rmtree(args.output_dir, ignore_errors=True)
        raise
    print(args.output_dir / "run_manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

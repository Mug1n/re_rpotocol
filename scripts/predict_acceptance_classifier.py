#!/usr/bin/env python3
"""Run the frozen C2 classifier on label-free M09 feature rows.

This intentionally consumes the compact evaluation manifest produced by
``train_acceptance_classifier.py`` rather than the research M11 artifact: the
latter has a separate contract.  Labels are rejected at this boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import joblib


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def predict(evaluation_path: Path, rows_path: Path, output_path: Path) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"output already exists: {output_path}")
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8-sig"))
    rows = json.loads(rows_path.read_text(encoding="utf-8-sig"))
    model_info = evaluation.get("model", {})
    model_path = evaluation_path.parent / str(model_info.get("artifact_ref", ""))
    if not model_path.is_file() or sha256(model_path) != model_info.get("sha256"):
        raise ValueError("model artifact is missing or its SHA-256 does not match evaluation.json")
    names = evaluation.get("feature_names")
    if not isinstance(names, list) or not names:
        raise ValueError("evaluation manifest has no fixed feature names")
    if rows.get("feature_definition_version") != evaluation.get("feature_definition_version"):
        raise ValueError("feature definition version mismatch")

    model = joblib.load(model_path)
    predictions = []
    for row in rows.get("rows", []):
        if row.get("labels") not in ({}, None):
            raise ValueError("inference rows must not contain labels")
        features = row.get("features", {})
        if set(features) != set(names):
            raise ValueError(f"feature set mismatch for {row.get('id')}")
        vector = []
        for name in names:
            value = features[name]
            if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ValueError(f"non-finite feature {name!r} for {row.get('id')}")
            vector.append(float(value))
        probabilities = model.predict_proba([vector])[0]
        predictions.append({
            "scope_id": row.get("id"),
            "predicted_label": str(model.predict([vector])[0]),
            "score_type": "class_probability",
            "score": float(max(probabilities)),
            "rejected": False,
        })
    output = {
        "schema_version": "0.1",
        "status": "ok",
        "source": {
            "evaluation_path": str(evaluation_path), "evaluation_sha256": sha256(evaluation_path),
            "rows_path": str(rows_path), "rows_sha256": sha256(rows_path),
        },
        "model": {"artifact_ref": str(model_info["artifact_ref"]), "sha256": model_info["sha256"],
                  "feature_definition_version": rows["feature_definition_version"]},
        "predictions": predictions,
        "warnings": ["Predictions are not ground truth and this small controlled capture batch is not generalizable."],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the frozen C2 classifier on label-free feature rows.")
    parser.add_argument("evaluation", type=Path)
    parser.add_argument("rows", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    predict(args.evaluation, args.rows, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

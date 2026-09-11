#!/usr/bin/env python3
"""Score a verified M11 model against a labeled held-out set without retraining.

Complements ``predict.py`` (label-free inference) with the closed-loop step that
measures accuracy: it loads a frozen ``classification.json`` + ``model.joblib``,
applies the same rejection threshold, and reports macro-F1 on the labeled rows.
Held-out labels outside the model's training classes are treated as open-set
samples, where the only correct outcome is rejection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

REJECTION_LABEL = "unknown"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_model(classification: Path) -> tuple[dict[str, Any], Any]:
    result = json.loads(classification.read_text(encoding="utf-8"))
    model_info = result.get("model") or {}
    artifact = model_info.get("artifact") or {}
    model_path = classification.parent / artifact.get("artifact_ref", "")
    if not model_path.is_file() or sha(model_path) != artifact.get("sha256"):
        raise ValueError("model artifact is missing or its hash does not match classification.json")
    import joblib
    return result, joblib.load(model_path)


def evaluate(classification: Path, rows_path: Path, output: Path, *, task: str) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    if not isinstance(task, str) or not task.strip():
        raise ValueError("task must be a non-empty label dimension")
    result, model = _load_model(classification)
    rows = json.loads(rows_path.read_text(encoding="utf-8"))
    if rows.get("feature_definition_version") != result.get("task", {}).get("feature_schema_version"):
        raise ValueError("feature definition version mismatch")
    names = (result.get("model") or {}).get("feature_names")
    if not isinstance(names, list) or not names:
        raise ValueError("classification has no fixed model feature names")
    reject_threshold = (result.get("parameters") or {}).get("reject_threshold", 0.5)
    if isinstance(reject_threshold, bool) or not isinstance(reject_threshold, (int, float)) \
            or not 0 <= reject_threshold <= 1:
        raise ValueError("classification has an invalid reject_threshold")

    model_classes = [str(klass) for klass in model.classes_]
    labeled: list[tuple[dict[str, Any], str]] = []
    for row in rows.get("rows", []):
        label = (row.get("labels") or {}).get(task)
        if label is None:
            continue
        if not isinstance(label, str) or not label:
            raise ValueError(f"row {row.get('id')} selected label must be a non-empty string")
        features = row.get("features", {})
        if set(features) != set(names) or any(
                not isinstance(features[n], (int, float)) or not math.isfinite(float(features[n]))
                for n in names):
            raise ValueError(f"invalid features for {row.get('id')}")
        labeled.append((row, label))
    if not labeled:
        raise ValueError("no labeled rows for the selected task")

    from sklearn.metrics import classification_report, confusion_matrix, f1_score

    identifiers = [row["id"] for row, _ in labeled]
    expected = [label for _, label in labeled]
    vectors = [[float(row["features"][n]) for n in names] for row, _ in labeled]
    probabilities = model.predict_proba(vectors)

    predictions: list[dict[str, Any]] = []
    id_expected: list[str] = []
    id_predicted: list[str] = []
    ood_count = 0
    ood_rejected = 0
    for identifier, true_label, proba in zip(identifiers, expected, probabilities):
        best = int(proba.argmax())
        score = float(proba[best])
        rejected = score < reject_threshold
        predicted = REJECTION_LABEL if rejected else model_classes[best]
        predictions.append({
            "scope_id": identifier,
            "predicted_label": predicted,
            "expected_label": true_label,
            "score_type": "class_probability",
            "score": score,
            "rejected": rejected,
        })
        if true_label in model_classes:
            id_expected.append(true_label)
            id_predicted.append(predicted)
        else:
            ood_count += 1
            if rejected:
                ood_rejected += 1

    rejected_count = sum(1 for label in id_predicted if label == REJECTION_LABEL)
    confusion_labels = model_classes + [REJECTION_LABEL]
    metrics = {
        "macro_f1": float(f1_score(id_expected, id_predicted, labels=model_classes,
                                   average="macro", zero_division=0)) if id_expected else None,
        "per_class": classification_report(id_expected, id_predicted, labels=model_classes,
                                           output_dict=True, zero_division=0) if id_expected else {},
        "confusion_matrix": {
            "labels": confusion_labels,
            "values": confusion_matrix(id_expected, id_predicted,
                                       labels=confusion_labels).tolist() if id_expected else [],
        },
        "majority_baseline": (max(id_expected.count(klass) for klass in model_classes) / len(id_expected)
                              if id_expected else None),
        "rejected_count": rejected_count,
        "rejection_rate": (rejected_count / len(id_expected) if id_expected else None),
        "out_of_distribution_count": ood_count,
        "out_of_distribution_rejected_count": ood_rejected,
    }

    out = {
        "schema_version": "0.1",
        "status": "evaluation_only",
        "source": {"classification_path": str(classification),
                   "classification_sha256": sha(classification),
                   "rows_path": str(rows_path), "rows_sha256": sha(rows_path)},
        "task": {"label_dimension": task, "classes": model_classes,
                 "held_out_classes": sorted(set(expected))},
        "model": {"artifact_ref": (result["model"]["artifact"] or {})["artifact_ref"],
                  "sha256": (result["model"]["artifact"] or {})["sha256"],
                  "feature_definition_version": rows["feature_definition_version"]},
        "metrics": metrics,
        "predictions": predictions,
        "warnings": [
            "Evaluation applies a frozen model to labeled held-out rows and does not retrain.",
            *([f"Open-set labels outside the model classes were only counted as rejected: "
               f"{sorted(set(expected) - set(model_classes))}."] if ood_count else []),
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classification", type=Path)
    parser.add_argument("rows", type=Path)
    parser.add_argument("--task", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    evaluate(args.classification, args.rows, args.output, task=args.task)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

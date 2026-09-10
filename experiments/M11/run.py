#!/usr/bin/env python3
"""M11 conditional grouped classifier with strict evidence boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1"
OUTPUT_SCHEMA = ROOT / "research" / "M11-behavior-classification" / "classification.schema.json"
FORBIDDEN_LABEL_DIMENSIONS = {"cluster_id"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid feature dataset: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != VERSION \
            or data.get("feature_definition_version") != VERSION \
            or not isinstance(data.get("rows"), list):
        raise ValueError("expected a version 0.1 dataset with feature_definition_version and rows")
    if set(data) - {"schema_version", "feature_definition_version", "rows"}:
        raise ValueError("feature dataset contains unsupported top-level fields")
    return data, hashlib.sha256(raw).hexdigest()


def _validate_rows(rows: list[Any], task: str) -> tuple[list[dict[str, Any]], list[str]]:
    identifiers: set[str] = set()
    feature_names: list[str] | None = None
    labeled: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"row {index} must be an object")
        if set(row) - {"id", "group_id", "labels", "features"}:
            raise ValueError(f"row {index} contains unsupported fields")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"row {index} must have a non-empty string id")
        if identifier in identifiers:
            raise ValueError(f"duplicate row id: {identifier}")
        identifiers.add(identifier)
        features = row.get("features")
        if not isinstance(features, dict) or not features:
            raise ValueError(f"row {identifier} must have a non-empty features object")
        names = sorted(features)
        if any(not isinstance(name, str) or not name for name in names):
            raise ValueError(f"row {identifier} has an invalid feature name")
        if feature_names is None:
            feature_names = names
        elif names != feature_names:
            raise ValueError("rows do not share one fixed feature definition")
        for name, value in features.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(float(value)):
                raise ValueError(f"row {identifier} feature {name} must be a finite number")
        labels = row.get("labels", {})
        if not isinstance(labels, dict):
            raise ValueError(f"row {identifier} labels must be an object")
        label = labels.get(task)
        if label is None:
            continue
        if not isinstance(label, str) or not label:
            raise ValueError(f"row {identifier} selected label must be a non-empty string")
        group_id = row.get("group_id")
        if not isinstance(group_id, str) or not group_id:
            raise ValueError(f"labeled row {identifier} must have a non-empty group_id")
        labeled.append(row)
    return labeled, feature_names or []


def base(
    source_path: Path, source_sha256: str, data: dict[str, Any], task: str,
    status: str, reason: str | None = None,
) -> dict[str, Any]:
    result = {
        "schema_version": VERSION,
        "source": {"module": "M09-compatible-feature-rows", "artifact_path": str(source_path),
                   "artifact_sha256": source_sha256, "record_count": len(data["rows"]),
                   "schema_version": data["schema_version"]},
        "status": status,
        "parameters": {"algorithm": "random_forest", "random_seed": 17,
                       "split_strategy": "grouped_holdout", "test_fraction": 0.25},
        "task": {"label_dimension": task, "classes": [],
                 "unknown_rejection": "not implemented; no unsupported labels are predicted",
                 "feature_schema_version": data["feature_definition_version"]},
        "split": {"group_key": "group_id", "train_count": 0, "test_count": 0,
                  "train_groups": [], "test_groups": [], "group_overlap": [],
                  "random_seed": 17},
        "model": None, "metrics": None, "predictions": [],
        "leakage_checks": {"groups_disjoint": True,
                           "preprocessing_fit_scope": "training_only when a model is trained",
                           "cluster_id_not_used_as_label": True},
        "warnings": [],
    }
    if reason:
        result["warnings"].append(reason)
    return result


def _choose_grouped_split(valid: list[dict[str, Any]], labels: list[str]):
    from sklearn.model_selection import GroupShuffleSplit

    expected = set(labels)
    groups = [row["group_id"] for row in valid]
    splitter = GroupShuffleSplit(n_splits=32, test_size=0.25, random_state=17)
    for train, test in splitter.split(valid, labels, groups):
        if len(train) and len(test) and {labels[index] for index in train} == expected \
                and {labels[index] for index in test} == expected:
            return train, test
    return None


def _publish(
    destination: Path, result: dict[str, Any], trained_model: Any = None,
    joblib_module: Any = None,
) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        if trained_model is not None:
            model_path = staging / "model.joblib"
            joblib_module.dump(trained_model, model_path)
            result["model"]["artifact"] = {
                "artifact_ref": "model.joblib", "sha256": sha(model_path),
                "length": model_path.stat().st_size, "format": "joblib",
            }
        jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
        (staging / "classification.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def analyze(input_path: Path, output_dir: Path, *, task: str) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    if not isinstance(task, str) or not task.strip():
        raise ValueError("task must be a non-empty label dimension")
    task = task.strip()
    if task.lower() in FORBIDDEN_LABEL_DIMENSIONS:
        raise ValueError("M04 cluster_id cannot be used as an M11 behavior label")
    data, source_sha256 = load(input_path)
    valid, feature_names = _validate_rows(data["rows"], task)
    result = base(input_path, source_sha256, data, task,
                  "empty" if not data["rows"] else "insufficient_labels")
    labels = [row["labels"][task] for row in valid]
    label_counts = Counter(labels)
    groups = {row["group_id"] for row in valid}
    result["task"]["classes"] = sorted(label_counts)
    trained_model = None
    joblib_module = None
    if not valid:
        result["warnings"].append(
            "No explicit labels with group_id and fixed feature rows were supplied.")
    elif len(label_counts) < 2:
        result["warnings"].append(
            "At least two explicit label classes are required; no accuracy was calculated.")
    elif len(groups) < 2:
        result["warnings"].append(
            "At least two groups are required for a leakage-resistant split.")
    else:
        try:
            import joblib
            import sklearn
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import classification_report, confusion_matrix, f1_score
        except ImportError:
            result["status"] = "dependency_unavailable"
            result["warnings"].append(
                "scikit-learn or joblib is unavailable; no model or metrics were produced.")
        else:
            split = _choose_grouped_split(valid, labels)
            if split is None:
                result["warnings"].append(
                    "No grouped split preserved every class in both train and test sets.")
            else:
                train, test = split
                train_groups = sorted({valid[index]["group_id"] for index in train})
                test_groups = sorted({valid[index]["group_id"] for index in test})
                if set(train_groups) & set(test_groups):
                    raise ValueError("invalid grouped split")
                features = [[float(row["features"][name]) for name in feature_names]
                            for row in valid]
                model = RandomForestClassifier(n_estimators=100, random_state=17, n_jobs=1)
                model.fit([features[index] for index in train], [labels[index] for index in train])
                test_features = [features[index] for index in test]
                expected = [labels[index] for index in test]
                predicted = model.predict(test_features)
                probabilities = model.predict_proba(test_features)
                classes = sorted(label_counts)
                report = classification_report(expected, predicted, labels=classes,
                                               output_dict=True, zero_division=0)
                result["status"] = "ok"
                result["split"] = {
                    "group_key": "group_id", "train_count": len(train),
                    "test_count": len(test), "train_groups": train_groups,
                    "test_groups": test_groups, "group_overlap": [], "random_seed": 17,
                }
                result["model"] = {
                    "algorithm": "RandomForestClassifier",
                    "parameters": {"n_estimators": 100, "random_state": 17, "n_jobs": 1},
                    "feature_names": feature_names,
                    "dependency": {"name": "scikit-learn", "version": sklearn.__version__},
                    "artifact": None,
                }
                result["metrics"] = {
                    "macro_f1": float(f1_score(expected, predicted, labels=classes,
                                               average="macro", zero_division=0)),
                    "per_class": report,
                    "confusion_matrix": {"labels": classes,
                                         "values": confusion_matrix(expected, predicted,
                                                                    labels=classes).tolist()},
                }
                result["predictions"] = [
                    {"scope_id": valid[index]["id"], "predicted_label": str(label),
                     "score_type": "class_probability", "score": float(max(probability)),
                     "rejected": False}
                    for index, label, probability in zip(test, predicted, probabilities)
                ]
                trained_model = model
                joblib_module = joblib
    return _publish(output_dir, result, trained_model, joblib_module)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train M11 only when explicit grouped labels are valid.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--task", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        analyze(args.input, args.output_dir, task=args.task)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m11: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "classification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

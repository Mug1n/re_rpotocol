#!/usr/bin/env python3
"""M11 conditional grouped classifier with strict evidence boundaries.

Trains a Random Forest baseline only when fixed-dimension finite features, an
explicit label dimension and a ``group_id`` are supplied. Evaluation uses either
the rows' explicit ``split`` partition (train/validation/test) or grouped
cross-validation when no split is present; in both cases groups never straddle
train and evaluation. Predictions below ``reject_threshold`` confidence are
marked rejected and labelled ``unknown`` instead of being forced into a class.
"""

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
REJECTION_LABEL = "unknown"
ROW_FIELDS = {"id", "group_id", "labels", "features", "split"}
DATASET_FIELDS = {"schema_version", "feature_definition_version", "rows",
                  "source", "feature_names", "warnings"}
SPLIT_VALUES = {"train", "validation", "test"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid feature dataset: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != VERSION \
            or not isinstance(data.get("feature_definition_version"), str) \
            or not data["feature_definition_version"] \
            or not isinstance(data.get("rows"), list):
        raise ValueError("expected a schema 0.1 dataset with feature_definition_version and rows")
    if set(data) - DATASET_FIELDS:
        raise ValueError("feature dataset contains unsupported top-level fields")
    return data, hashlib.sha256(raw).hexdigest()


def _validate_rows(rows: list[Any], task: str) -> tuple[list[dict[str, Any]], list[str]]:
    identifiers: set[str] = set()
    feature_names: list[str] | None = None
    labeled: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"row {index} must be an object")
        if set(row) - ROW_FIELDS:
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
        split = row.get("split")
        if split is not None and split not in SPLIT_VALUES:
            raise ValueError(f"row {identifier} split must be one of train/validation/test")
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
                   "schema_version": VERSION},
        "status": status,
        "parameters": {"algorithm": "random_forest", "random_seed": 17,
                       "split_strategy": "grouped_cv", "cv_folds": 5,
                       "class_weight": "balanced", "reject_threshold": 0.5},
        "task": {"label_dimension": task, "classes": [],
                 "unknown_rejection": f"max class probability below reject_threshold is labelled '{REJECTION_LABEL}'",
                 "feature_schema_version": data["feature_definition_version"]},
        "split": {"strategy": "grouped_cv", "group_key": "group_id", "random_seed": 17,
                  "group_overlap": [], "train_count": 0, "train_groups": [],
                  "test_count": 0, "test_groups": [], "validation_count": 0,
                  "validation_groups": [], "cv_folds": 0},
        "model": None, "metrics": None, "predictions": [],
        "leakage_checks": {"groups_disjoint": True,
                           "preprocessing_fit_scope": "training_only when a model is trained",
                           "cluster_id_not_used_as_label": True},
        "warnings": [],
    }
    if reason:
        result["warnings"].append(reason)
    return result


def _feature_matrix(rows: list[dict[str, Any]], feature_names: list[str]) -> list[list[float]]:
    return [[float(row["features"][name]) for name in feature_names] for row in rows]


def _labels(rows: list[dict[str, Any]], task: str) -> list[str]:
    return [row["labels"][task] for row in rows]


def _majority_baseline(expected: list[str], classes: list[str]) -> float:
    if not expected:
        return 0.0
    return max(expected.count(klass) for klass in classes) / len(expected)


def _predict_with_rejection(
    model: Any, features: list[list[float]], classes: list[str], reject_threshold: float,
    identifiers: list[str],
) -> list[dict[str, Any]]:
    probabilities = model.predict_proba(features)
    predictions: list[dict[str, Any]] = []
    for identifier, proba in zip(identifiers, probabilities):
        best = int(proba.argmax())
        max_probability = float(proba[best])
        rejected = max_probability < reject_threshold
        predictions.append({
            "scope_id": identifier,
            "predicted_label": REJECTION_LABEL if rejected else classes[best],
            "score_type": "class_probability",
            "score": max_probability,
            "rejected": rejected,
        })
    return predictions


def _evaluate(
    model: Any, features: list[list[float]], expected: list[str],
    classes: list[str], identifiers: list[str], reject_threshold: float,
) -> dict[str, Any]:
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    predicted = model.predict(features)
    report = classification_report(expected, predicted, labels=classes,
                                   output_dict=True, zero_division=0)
    metrics = {
        "macro_f1": float(f1_score(expected, predicted, labels=classes,
                                   average="macro", zero_division=0)),
        "per_class": report,
        "confusion_matrix": {"labels": classes,
                             "values": confusion_matrix(expected, predicted,
                                                        labels=classes).tolist()},
        "validation_macro_f1": None, "cv_folds": None,
        "cv_macro_f1_mean": None, "cv_macro_f1_std": None, "cv_fold_scores": None,
        "majority_baseline": _majority_baseline(expected, classes),
    }
    predictions = _predict_with_rejection(model, features, classes, reject_threshold, identifiers)
    return metrics, predictions


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


def _new_model():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=100, random_state=17, n_jobs=1,
                                  class_weight="balanced")


def analyze(
    input_path: Path, output_dir: Path, *, task: str,
    reject_threshold: float = 0.5, cv_folds: int = 5,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    if not isinstance(task, str) or not task.strip():
        raise ValueError("task must be a non-empty label dimension")
    task = task.strip()
    if task.lower() in FORBIDDEN_LABEL_DIMENSIONS:
        raise ValueError("M04 cluster_id cannot be used as an M11 behavior label")
    if isinstance(reject_threshold, bool) or not math.isfinite(reject_threshold) \
            or not 0 <= reject_threshold <= 1:
        raise ValueError("reject_threshold must be a finite number between 0 and 1")
    if isinstance(cv_folds, bool) or cv_folds <= 1:
        raise ValueError("cv_folds must be an integer greater than 1")

    data, source_sha256 = load(input_path)
    labeled, feature_names = _validate_rows(data["rows"], task)
    result = base(input_path, source_sha256, data, task,
                  "empty" if not data["rows"] else "insufficient_labels")
    result["parameters"]["reject_threshold"] = reject_threshold
    result["parameters"]["cv_folds"] = cv_folds
    labels = _labels(labeled, task)
    label_counts = Counter(labels)
    classes = sorted(label_counts)
    groups = {row["group_id"] for row in labeled}
    result["task"]["classes"] = classes

    trained_model = None
    joblib_module = None
    if not labeled:
        result["warnings"].append(
            "No explicit labels with group_id and fixed feature rows were supplied.")
    elif len(label_counts) < 2:
        result["warnings"].append(
            "At least two explicit label classes are required; no accuracy was calculated.")
    elif len(groups) < 2:
        result["warnings"].append(
            "At least two groups are required for a leakage-resistant evaluation.")
    else:
        try:
            import joblib
            import sklearn
            from sklearn.metrics import f1_score
        except ImportError:
            result["status"] = "dependency_unavailable"
            result["warnings"].append(
                "scikit-learn or joblib is unavailable; no model or metrics were produced.")
        else:
            has_split = [row.get("split") is not None for row in labeled]
            if all(has_split):
                strategy = "explicit_partition"
            elif not any(has_split):
                strategy = "grouped_cv"
            else:
                raise ValueError("rows inconsistently specify split assignments")
            result["parameters"]["split_strategy"] = strategy
            result["split"]["strategy"] = strategy

            if strategy == "explicit_partition":
                trained_model, joblib_module = _run_explicit_partition(
                    labeled, feature_names, classes, task, reject_threshold, result)
            else:
                trained_model, joblib_module = _run_grouped_cv(
                    labeled, feature_names, classes, task, reject_threshold,
                    cv_folds, result, joblib, sklearn)
    return _publish(output_dir, result, trained_model, joblib_module)


def _run_explicit_partition(
    labeled: list[dict[str, Any]], feature_names: list[str], classes: list[str],
    task: str, reject_threshold: float, result: dict[str, Any],
) -> tuple[Any, Any]:
    import joblib
    import sklearn
    from sklearn.ensemble import RandomForestClassifier

    partitions = {key: [row for row in labeled if row.get("split") == key]
                  for key in SPLIT_VALUES}
    if not partitions["train"] or not partitions["test"]:
        result["warnings"].append(
            "Explicit split lacks a train or test partition; no accuracy was calculated.")
        return None, None
    if {row["labels"][task] for row in partitions["train"]} != set(classes) \
            or {row["labels"][task] for row in partitions["test"]} != set(classes):
        result["warnings"].append(
            "Explicit split did not preserve every class in both train and test; no accuracy was calculated.")
        return None, None

    model = _new_model()
    model.fit(_feature_matrix(partitions["train"], feature_names),
              _labels(partitions["train"], task))

    test_features = _feature_matrix(partitions["test"], feature_names)
    metrics, predictions = _evaluate(
        model, test_features, _labels(partitions["test"], task), classes,
        [row["id"] for row in partitions["test"]], reject_threshold)
    if partitions["validation"]:
        from sklearn.metrics import f1_score
        validation_predicted = model.predict(_feature_matrix(partitions["validation"], feature_names))
        metrics["validation_macro_f1"] = float(f1_score(
            _labels(partitions["validation"], task), validation_predicted,
            labels=classes, average="macro", zero_division=0))

    result["status"] = "ok"
    result["split"].update({
        "train_count": len(partitions["train"]),
        "train_groups": sorted({row["group_id"] for row in partitions["train"]}),
        "test_count": len(partitions["test"]),
        "test_groups": sorted({row["group_id"] for row in partitions["test"]}),
        "validation_count": len(partitions["validation"]),
        "validation_groups": sorted({row["group_id"] for row in partitions["validation"]}),
        "cv_folds": 0,
    })
    result["model"] = {
        "algorithm": "RandomForestClassifier",
        "parameters": {"n_estimators": 100, "random_state": 17, "n_jobs": 1,
                       "class_weight": "balanced"},
        "feature_names": feature_names,
        "dependency": {"name": "scikit-learn", "version": sklearn.__version__},
        "artifact": None,
    }
    result["metrics"] = metrics
    result["predictions"] = predictions
    return model, joblib


def _run_grouped_cv(
    labeled: list[dict[str, Any]], feature_names: list[str], classes: list[str],
    task: str, reject_threshold: float, cv_folds: int, result: dict[str, Any],
    joblib: Any, sklearn: Any,
) -> tuple[Any, Any]:
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import GroupKFold

    groups_list = [row["group_id"] for row in labeled]
    unique_groups = sorted(set(groups_list))
    n_splits = min(cv_folds, len(unique_groups))
    fold_splitter = GroupKFold(n_splits=n_splits)
    features = _feature_matrix(labeled, feature_names)
    labels = _labels(labeled, task)
    identifiers = [row["id"] for row in labeled]

    oof_expected: list[str] = []
    oof_predicted: list[str] = []
    fold_scores: list[float] = []
    fold_probabilities: list[list[float]] = []
    fold_identifiers: list[str] = []
    valid_folds = 0
    for train_index, test_index in fold_splitter.split(labeled, labels, groups_list):
        train_labels = {labels[index] for index in train_index}
        test_labels = {labels[index] for index in test_index}
        if train_labels != set(classes) or test_labels != set(classes):
            result["warnings"].append(
                "A grouped CV fold did not preserve every class in both train and test; fold skipped.")
            continue
        valid_folds += 1
        fold_model = _new_model()
        fold_model.fit([features[index] for index in train_index],
                       [labels[index] for index in train_index])
        fold_expected = [labels[index] for index in test_index]
        fold_predicted = fold_model.predict([features[index] for index in test_index])
        oof_expected.extend(fold_expected)
        oof_predicted.extend(fold_predicted)
        fold_probabilities.extend(fold_model.predict_proba(
            [features[index] for index in test_index]))
        fold_identifiers.extend([identifiers[index] for index in test_index])
        fold_scores.append(float(f1_score(fold_expected, fold_predicted,
                                          labels=classes, average="macro", zero_division=0)))

    if valid_folds == 0:
        result["warnings"].append(
            "Grouped cross-validation could not preserve every class in any fold; no accuracy was calculated.")
        return None, None

    report = classification_report(oof_expected, oof_predicted, labels=classes,
                                   output_dict=True, zero_division=0)
    mean_f1 = float(sum(fold_scores) / len(fold_scores))
    variance = float(sum((score - mean_f1) ** 2 for score in fold_scores) / len(fold_scores)) \
        if len(fold_scores) > 1 else 0.0
    metrics = {
        "macro_f1": float(f1_score(oof_expected, oof_predicted, labels=classes,
                                   average="macro", zero_division=0)),
        "per_class": report,
        "confusion_matrix": {"labels": classes,
                             "values": confusion_matrix(oof_expected, oof_predicted,
                                                        labels=classes).tolist()},
        "validation_macro_f1": None, "cv_folds": valid_folds,
        "cv_macro_f1_mean": mean_f1, "cv_macro_f1_std": math.sqrt(variance),
        "cv_fold_scores": fold_scores,
        "majority_baseline": _majority_baseline(oof_expected, classes),
    }
    predictions = _predict_with_rejection_probabilities(
        fold_identifiers, fold_probabilities, classes, reject_threshold)

    model = _new_model()
    model.fit(features, labels)

    result["status"] = "ok"
    result["split"].update({
        "train_count": len(labeled),
        "train_groups": unique_groups,
        "test_count": 0, "test_groups": [],
        "validation_count": 0, "validation_groups": [],
        "cv_folds": n_splits,
    })
    result["model"] = {
        "algorithm": "RandomForestClassifier",
        "parameters": {"n_estimators": 100, "random_state": 17, "n_jobs": 1,
                       "class_weight": "balanced"},
        "feature_names": feature_names,
        "dependency": {"name": "scikit-learn", "version": sklearn.__version__},
        "artifact": None,
    }
    result["metrics"] = metrics
    result["predictions"] = predictions
    return model, joblib


def _predict_with_rejection_probabilities(
    identifiers: list[str], probabilities: list[list[float]], classes: list[str],
    reject_threshold: float,
) -> list[dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    for identifier, proba in zip(identifiers, probabilities):
        best = int(max(range(len(proba)), key=proba.__getitem__))
        max_probability = float(proba[best])
        rejected = max_probability < reject_threshold
        predictions.append({
            "scope_id": identifier,
            "predicted_label": REJECTION_LABEL if rejected else classes[best],
            "score_type": "class_probability",
            "score": max_probability,
            "rejected": rejected,
        })
    return predictions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train M11 only when explicit grouped labels are valid.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--task", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--reject-threshold", type=float, default=0.5)
    parser.add_argument("--cv-folds", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        analyze(args.input, args.output_dir, task=args.task,
                reject_threshold=args.reject_threshold, cv_folds=args.cv_folds)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m11: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "classification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

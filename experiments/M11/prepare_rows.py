#!/usr/bin/env python3
"""Attach labels, group ids and optional split assignments to label-free M11 rows.

This is the isolated training-preparation step: it joins externally supplied
labels and group metadata onto the fixed feature rows emitted by
``build_rows.py`` (or any dataset adapter producing the same row contract). No
labels are ever invented here; every assignment must name an existing row id
and carry a non-empty group id so the classifier can isolate groups.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

VERSION = "0.1"
ROW_FIELDS = {"id", "group_id", "labels", "features", "split"}
ROWS_FIELDS = {"schema_version", "feature_definition_version", "rows",
               "source", "feature_names", "warnings"}
ASSIGNMENT_FIELDS = {"id", "labels", "group_id", "split"}
SPLIT_VALUES = {"train", "validation", "test"}


def _load_rows(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != VERSION \
            or not isinstance(data.get("feature_definition_version"), str) \
            or not data["feature_definition_version"] \
            or not isinstance(data.get("rows"), list):
        raise ValueError("expected a schema 0.1 feature-rows file")
    if set(data) - ROWS_FIELDS:
        raise ValueError("feature-rows file contains unsupported top-level fields")
    return data


def _load_assignments(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != VERSION \
            or not isinstance(data.get("assignments"), list):
        raise ValueError("expected a schema 0.1 labels file with an assignments list")
    return data["assignments"]


def prepare(rows_path: Path, labels_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    rows_data = _load_rows(rows_path)
    rows = rows_data["rows"]
    identifiers = {row.get("id") for row in rows}
    assignments = _load_assignments(labels_path)

    seen: set[str] = set()
    for assignment in assignments:
        if not isinstance(assignment, dict) or set(assignment) - ASSIGNMENT_FIELDS:
            raise ValueError("assignment contains unsupported fields")
        identifier = assignment.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("assignment must have a non-empty string id")
        if identifier in seen:
            raise ValueError(f"duplicate assignment id: {identifier}")
        seen.add(identifier)
        if identifier not in identifiers:
            raise ValueError(f"assignment id {identifier} is not present in the feature rows")
        labels = assignment.get("labels")
        if not isinstance(labels, dict) or not labels or any(
                not isinstance(value, str) or not value for value in labels.values()):
            raise ValueError(f"assignment {identifier} must have non-empty string labels")
        group_id = assignment.get("group_id")
        if not isinstance(group_id, str) or not group_id:
            raise ValueError(f"assignment {identifier} must have a non-empty group_id")
        split = assignment.get("split")
        if split is not None and split not in SPLIT_VALUES:
            raise ValueError(f"assignment {identifier} split must be train/validation/test")

    by_id = {assignment["id"]: assignment for assignment in assignments}
    prepared_rows = []
    for row in rows:
        assignment = by_id.get(row.get("id"))
        if assignment is None:
            prepared_rows.append(row)
            continue
        prepared_rows.append({
            "id": row["id"],
            "group_id": assignment["group_id"],
            "labels": assignment["labels"],
            "features": row["features"],
            **({"split": assignment["split"]} if assignment.get("split") is not None else {}),
        })

    result = {
        "schema_version": VERSION,
        "feature_definition_version": rows_data["feature_definition_version"],
        "rows": prepared_rows,
    }
    for key in ("source", "feature_names", "warnings"):
        if key in rows_data:
            result[key] = rows_data[key]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rows", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    prepare(args.rows, args.labels, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

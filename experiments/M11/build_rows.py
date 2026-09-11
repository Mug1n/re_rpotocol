#!/usr/bin/env python3
"""Build fixed M11 feature rows from an M09 artifact; labels stay external."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import FEATURE_NAMES, FEATURE_SET_VERSION, build_features

VERSION = "0.1"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    raw = json.loads(source.read_text(encoding="utf-8"))
    if raw.get("schema_version") != VERSION or not isinstance(raw.get("flows"), list):
        raise ValueError("expected M09 flow_features.json")
    rows = []
    warnings = ["Labels and split assignments are intentionally absent; add them only in the isolated training-preparation step."]
    for flow in sorted(raw["flows"], key=lambda item: item["flow_id"]):
        features, missing = build_features(flow)
        if features is None:
            reasons = ", ".join(missing) if missing else "no packets"
            warnings.append(f"skipped flow {flow['flow_id']}: missing {reasons}")
            continue
        rows.append({
            "id": flow["flow_id"],
            "group_id": None,
            "labels": {},
            "features": {key: float(features[key]) for key in FEATURE_NAMES},
        })
    result = {
        "schema_version": VERSION,
        "feature_definition_version": FEATURE_SET_VERSION,
        "source": {"module": "M09", "artifact_path": str(source),
                   "artifact_sha256": digest(source)},
        "feature_names": list(FEATURE_NAMES),
        "rows": rows,
        "warnings": warnings,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args(argv)
    build(a.input, a.output)
    print(a.output)


if __name__ == "__main__":
    main()

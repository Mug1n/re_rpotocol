#!/usr/bin/env python3
"""Reproduce and verify the M11 ISCX VPN 2016 external evaluation.

The repository intentionally does not contain the 2.3 GB source archive.  The
``verify`` command therefore checks the committed evidence without raw data;
``prepare`` validates user-supplied captures and rebuilds M01/M09/M11 rows;
``train`` runs the two recorded group-disjoint folds and emits a new evaluation.
No command downloads data or overwrites an existing output directory/file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "external" / "iscx-vpn-2016" / "manifest.json"
DEFAULT_EVALUATION = ROOT / "data" / "external" / "iscx-vpn-2016" / "evaluation.json"
FEATURE_NAMES = [
    "packet_count", "byte_count", "packet_length_mean", "packet_length_p95",
    "packet_length_median", "node0_to_node1_packet_ratio",
    "node0_to_node1_byte_ratio", "direction_switches_per_packet",
    "duration_seconds", "iat_mean", "iat_p95", "iat_cv", "burst_count",
    "burst_avg_packets", "burst_max_packets", "retransmission_ratio",
    "gap_or_loss_ratio",
]
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TOLERANCE = 1e-12


class EvidenceError(ValueError):
    """Raised when recorded or rebuilt evidence violates the protocol."""


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"expected a JSON object: {path}")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise EvidenceError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _is_sha256(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _close(actual: Any, expected: Any, label: str) -> None:
    try:
        valid = math.isclose(float(actual), float(expected), rel_tol=TOLERANCE, abs_tol=TOLERANCE)
    except (TypeError, ValueError):
        valid = False
    _expect(valid, f"{label}: expected {expected!r}, got {actual!r}")


def _f1(matrix: list[list[int]], index: int) -> float:
    true_positive = matrix[index][index]
    false_positive = sum(row[index] for row in matrix) - true_positive
    false_negative = sum(matrix[index]) - true_positive
    denominator = 2 * true_positive + false_positive + false_negative
    return 0.0 if denominator == 0 else 2 * true_positive / denominator


def validate_evidence(manifest: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    """Validate cross-file counts, folds, hashes and all reported metrics."""
    _expect(manifest.get("schema_version") == "0.1", "manifest schema_version must be 0.1")
    sessions = manifest.get("sessions")
    _expect(isinstance(sessions, list) and sessions, "manifest sessions must be non-empty")
    _expect(manifest.get("sessions_total") == len(sessions), "sessions_total mismatch")
    archive = manifest.get("archive", {})
    _expect(isinstance(archive.get("bytes"), int) and archive["bytes"] > 0,
            "archive bytes must be positive")
    _expect(_is_sha256(archive.get("sha256")),
            "archive sha256 must contain 64 hex characters")

    by_id: dict[str, dict[str, Any]] = {}
    row_counts: Counter[str] = Counter()
    folds: dict[str, list[str]] = {}
    excluded: Counter[str] = Counter()
    for item in sessions:
        _expect(isinstance(item, dict), "each session must be an object")
        sid = item.get("session_id")
        _expect(isinstance(sid, str) and sid and sid not in by_id, f"invalid/duplicate session_id: {sid!r}")
        by_id[sid] = item
        label = item.get("application_label")
        flow_count = item.get("flows")
        _expect(isinstance(label, str) and label, f"{sid}: missing application_label")
        _expect(isinstance(flow_count, int) and flow_count >= 0, f"{sid}: invalid flow count")
        for capture_key in ("source_capture", "analysis_capture"):
            capture = item.get(capture_key, {})
            _expect(isinstance(capture.get("bytes"), int) and capture["bytes"] > 0,
                    f"{sid}: invalid {capture_key} byte count")
            digest = capture.get("sha256")
            _expect(_is_sha256(digest),
                    f"{sid}: invalid {capture_key} sha256")
        feature_hash = item.get("flow_features_sha256")
        _expect(_is_sha256(feature_hash),
                f"{sid}: invalid flow_features_sha256")
        held_out = item.get("held_out_in_folds")
        _expect(isinstance(held_out, list) and len(held_out) == len(set(held_out)),
                f"{sid}: invalid held_out_in_folds")
        if item.get("used_in_evaluation") is True:
            _expect(len(held_out) == 1, f"{sid}: used session must be held out exactly once")
            row_counts[label] += flow_count
            folds.setdefault(held_out[0], []).append(sid)
        else:
            _expect(not held_out, f"{sid}: excluded session cannot be held out")
            # Zero-flow captures contribute no candidate row/class to the
            # evaluation.  ``excluded_classes`` records only otherwise usable
            # classes rejected by the group-disjoint protocol.
            if flow_count > 0:
                excluded[label] += 1
    used = sum(item.get("used_in_evaluation") is True for item in sessions)
    _expect(manifest.get("sessions_used") == used, "sessions_used mismatch")

    _expect(evaluation.get("schema_version") == "0.1", "evaluation schema_version must be 0.1")
    feature_set = evaluation.get("feature_set", {})
    _expect(feature_set.get("feature_definition_version") == "0.2", "unexpected feature version")
    _expect(feature_set.get("feature_names") == FEATURE_NAMES, "feature name/order mismatch")
    _expect(feature_set.get("feature_count") == len(FEATURE_NAMES), "feature_count mismatch")
    rows = evaluation.get("rows", {})
    _expect(rows.get("per_class") == dict(row_counts), "evaluation per-class row counts mismatch")
    _expect(rows.get("total") == sum(row_counts.values()), "evaluation total row count mismatch")
    _expect(evaluation.get("excluded_classes") == dict(excluded), "excluded class counts mismatch")

    split_folds = evaluation.get("split", {}).get("folds")
    result_folds = evaluation.get("results", {}).get("folds")
    _expect(isinstance(split_folds, list) and isinstance(result_folds, list), "fold lists are required")
    _expect(len(split_folds) == len(result_folds) == len(folds) >= 2, "fold count mismatch")
    result_by_fold = {item.get("fold"): item for item in result_folds}
    macro_values: list[float] = []
    baseline_values: list[float] = []
    all_labels = sorted(row_counts)
    for split in split_folds:
        fold = split.get("fold")
        expected_sessions = sorted(folds.get(fold, []))
        _expect(split.get("test_sessions") == expected_sessions, f"{fold}: test session list mismatch")
        expected_rows = sum(by_id[sid]["flows"] for sid in expected_sessions)
        _expect(split.get("test_rows") == expected_rows, f"{fold}: test row count mismatch")
        result = result_by_fold.get(fold)
        _expect(isinstance(result, dict), f"{fold}: missing result")
        matrix_obj = result.get("confusion_matrix", {})
        labels = matrix_obj.get("labels")
        matrix = matrix_obj.get("values")
        _expect(labels == all_labels, f"{fold}: confusion labels mismatch")
        _expect(isinstance(matrix, list) and len(matrix) == len(labels), f"{fold}: invalid matrix rows")
        _expect(all(isinstance(row, list) and len(row) == len(labels) for row in matrix),
                f"{fold}: invalid matrix columns")
        _expect(all(isinstance(value, int) and value >= 0 for row in matrix for value in row),
                f"{fold}: matrix values must be non-negative integers")
        _expect(sum(sum(row) for row in matrix) == expected_rows, f"{fold}: matrix total mismatch")
        expected_by_label = Counter()
        for sid in expected_sessions:
            expected_by_label[by_id[sid]["application_label"]] += by_id[sid]["flows"]
        _expect([sum(row) for row in matrix] == [expected_by_label[label] for label in labels],
                f"{fold}: matrix truth marginals mismatch")
        f1_values = [_f1(matrix, index) for index in range(len(labels))]
        for label, value in zip(labels, f1_values):
            _close(result.get("per_class_f1", {}).get(label), value, f"{fold}/{label} F1")
        macro = sum(f1_values) / len(f1_values)
        correct = sum(matrix[index][index] for index in range(len(labels)))
        baseline = max(expected_by_label.values()) / expected_rows
        _close(result.get("macro_f1"), macro, f"{fold} macro-F1")
        _close(result.get("accuracy"), correct / expected_rows, f"{fold} accuracy")
        _close(result.get("majority_baseline"), baseline, f"{fold} majority baseline")
        macro_values.append(macro)
        baseline_values.append(baseline)

    results = evaluation["results"]
    mean_macro = sum(macro_values) / len(macro_values)
    mean_baseline = sum(baseline_values) / len(baseline_values)
    _close(results.get("mean_test_macro_f1"), mean_macro, "mean macro-F1")
    _close(results.get("mean_majority_baseline"), mean_baseline, "mean majority baseline")
    _close(results.get("lift_over_majority"), mean_macro - mean_baseline, "lift over majority")
    return {"sessions": len(sessions), "sessions_used": used, "rows": sum(row_counts.values()),
            "folds": len(folds), "mean_macro_f1": mean_macro}


def _check_file(path: Path, evidence: dict[str, Any], label: str) -> None:
    _expect(path.is_file(), f"{label} not found: {path}")
    _expect(path.stat().st_size == evidence["bytes"], f"{label} byte count mismatch")
    _expect(_sha256(path) == evidence["sha256"], f"{label} sha256 mismatch")


def _find_captures(raw_root: Path, sessions: list[dict[str, Any]]) -> dict[str, Path]:
    _expect(raw_root.is_dir(), f"raw capture root not found: {raw_root}")
    wanted = {item["session_id"].casefold(): item["session_id"] for item in sessions}
    _expect(len(wanted) == len(sessions), "session IDs must be unique ignoring case")
    matches: dict[str, list[Path]] = {sid: [] for sid in wanted.values()}
    for path in raw_root.rglob("*"):
        if path.is_file() and path.suffix.casefold() in CAPTURE_SUFFIXES:
            sid = wanted.get(path.stem.casefold())
            if sid:
                matches[sid].append(path)
    ambiguous = {sid: paths for sid, paths in matches.items() if len(paths) != 1}
    if ambiguous:
        detail = "; ".join(f"{sid}={len(paths)}" for sid, paths in sorted(ambiguous.items()))
        raise EvidenceError(f"each manifest session needs exactly one source capture ({detail})")
    return {sid: paths[0] for sid, paths in matches.items()}


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if completed.returncode:
        output = (completed.stderr or completed.stdout).strip()
        raise EvidenceError(f"command failed ({completed.returncode}): {' '.join(command)}\n{output}")


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    manifest = _load(args.manifest)
    sessions = manifest.get("sessions", [])
    _expect(isinstance(sessions, list) and sessions, "manifest contains no sessions")
    _expect(not args.work_root.exists(), f"work root already exists: {args.work_root}")
    captures = _find_captures(args.raw_root, sessions)
    # Preflight the complete raw set before producing expensive derived outputs.
    for item in sessions:
        _check_file(captures[item["session_id"]], item["source_capture"], item["session_id"])
    args.work_root.mkdir(parents=True)

    rows_by_session: dict[str, list[dict[str, Any]]] = {}
    feature_hashes: dict[str, dict[str, Any]] = {}
    for item in sessions:
        sid = item["session_id"]
        session_root = args.work_root / "sessions" / sid
        session_root.mkdir(parents=True)
        analysis_capture = session_root / "analysis.pcapng"
        source = captures[sid]
        if item["analysis_capture"].get("truncated_to_packet_cap"):
            _run([str(args.tshark), "-r", str(source), "-c",
                  str(item["analysis_capture"]["packet_cap"]), "-w", str(analysis_capture)])
        else:
            shutil.copyfile(source, analysis_capture)
        _check_file(analysis_capture, item["analysis_capture"], f"{sid} analysis capture")
        m01_dir = session_root / "m01"
        m09_dir = session_root / "m09"
        row_path = session_root / "rows.json"
        _run([sys.executable, "-B", str(ROOT / "experiments/M01/run.py"), str(analysis_capture),
              "--output-dir", str(m01_dir), "--tshark", str(args.tshark),
              "--capinfos", str(args.capinfos)])
        _run([sys.executable, "-B", str(ROOT / "experiments/M09/run.py"),
              str(m01_dir / "result.json"), "--output-dir", str(m09_dir)])
        feature_path = m09_dir / "flow_features.json"
        rebuilt_feature_hash = _sha256(feature_path)
        feature_hashes[sid] = {
            "recorded": item["flow_features_sha256"],
            "rebuilt": rebuilt_feature_hash,
            "matches_recorded": rebuilt_feature_hash == item["flow_features_sha256"],
        }
        _run([sys.executable, "-B", str(ROOT / "experiments/M11/build_rows.py"),
              str(feature_path), "--output", str(row_path)])
        built = _load(row_path)
        _expect(len(built.get("rows", [])) == item["flows"], f"{sid}: rebuilt flow count mismatch")
        rows_by_session[sid] = built["rows"]

    fold_names = sorted({fold for item in sessions for fold in item["held_out_in_folds"]})
    fold_records = []
    used_sessions = [item for item in sessions if item["used_in_evaluation"]]
    for fold in fold_names:
        merged_rows = []
        for item in used_sessions:
            sid = item["session_id"]
            split = "test" if fold in item["held_out_in_folds"] else "train"
            for row in rows_by_session[sid]:
                merged_rows.append({**row, "id": f"{sid}:{row['id']}", "group_id": sid,
                                    "labels": {"application": item["application_label"]},
                                    "split": split})
        dataset = {"schema_version": "0.1", "feature_definition_version": "0.2",
                   "source": {"module": "ISCX-reproduction", "manifest": str(args.manifest)},
                   "feature_names": FEATURE_NAMES, "rows": merged_rows, "warnings": []}
        fold_path = args.work_root / "folds" / f"{fold}.json"
        _write_new(fold_path, dataset)
        fold_records.append({"fold": fold, "dataset": str(fold_path.relative_to(args.work_root)),
                             "sha256": _sha256(fold_path), "rows": len(merged_rows)})
    prepared = {"schema_version": "0.1", "source_manifest_sha256": _sha256(args.manifest),
                "feature_hash_note": "M09 JSON hashes include artifact paths; recorded values are diagnostic, while capture hashes and semantic counts are strict.",
                "flow_feature_hashes": feature_hashes, "folds": fold_records}
    _write_new(args.work_root / "prepared.json", prepared)
    return prepared


def _evaluation_from_runs(template: dict[str, Any], work_root: Path,
                          run_root: Path) -> dict[str, Any]:
    output = json.loads(json.dumps(template))
    result_folds = []
    for split in output["split"]["folds"]:
        fold = split["fold"]
        artifact = _load(run_root / fold / "classification.json")
        _expect(artifact.get("status") == "ok", f"{fold}: M11 did not produce an ok result")
        metrics = artifact["metrics"]
        matrix = metrics["confusion_matrix"]
        result_folds.append({"fold": fold, "macro_f1": metrics["macro_f1"],
                             "majority_baseline": metrics["majority_baseline"],
                             "accuracy": sum(matrix["values"][i][i] for i in range(len(matrix["labels"]))) / split["test_rows"],
                             "per_class_f1": {label: metrics["per_class"][label]["f1-score"] for label in matrix["labels"]},
                             "confusion_matrix": matrix, "warnings": artifact.get("warnings", [])})
    macros = [item["macro_f1"] for item in result_folds]
    baselines = [item["majority_baseline"] for item in result_folds]
    output["results"] = {"folds": result_folds,
                         "mean_test_macro_f1": sum(macros) / len(macros),
                         "mean_majority_baseline": sum(baselines) / len(baselines),
                         "lift_over_majority": sum(macros) / len(macros) - sum(baselines) / len(baselines)}
    return output


def train(args: argparse.Namespace) -> dict[str, Any]:
    prepared = _load(args.work_root / "prepared.json")
    template = _load(args.expected_evaluation)
    _expect(not args.run_root.exists(), f"run root already exists: {args.run_root}")
    args.run_root.mkdir(parents=True)
    for item in prepared.get("folds", []):
        dataset = args.work_root / item["dataset"]
        _expect(_sha256(dataset) == item["sha256"], f"{item['fold']}: prepared dataset hash mismatch")
        _run([sys.executable, "-B", str(ROOT / "experiments/M11/run.py"), str(dataset),
              "--task", "application", "--output-dir", str(args.run_root / item["fold"])])
    evaluation = _evaluation_from_runs(template, args.work_root, args.run_root)
    validate_evidence(_load(args.manifest), evaluation)
    _write_new(args.output, evaluation)
    return evaluation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify", help="validate committed evidence without raw captures")
    verify_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    verify_parser.add_argument("--evaluation", type=Path, default=DEFAULT_EVALUATION)
    verify_parser.add_argument("--archive", type=Path, help="optionally verify the downloaded 2.3 GB archive")
    prepare_parser = subparsers.add_parser("prepare", help="rebuild fold datasets from hash-matched captures")
    prepare_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    prepare_parser.add_argument("--raw-root", type=Path, required=True)
    prepare_parser.add_argument("--work-root", type=Path, required=True)
    prepare_parser.add_argument("--tshark", type=Path, required=True)
    prepare_parser.add_argument("--capinfos", type=Path, required=True)
    train_parser = subparsers.add_parser("train", help="train both prepared folds and emit evaluation JSON")
    train_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    train_parser.add_argument("--expected-evaluation", type=Path, default=DEFAULT_EVALUATION)
    train_parser.add_argument("--work-root", type=Path, required=True)
    train_parser.add_argument("--run-root", type=Path, required=True)
    train_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            manifest = _load(args.manifest)
            summary = validate_evidence(manifest, _load(args.evaluation))
            if args.archive:
                _check_file(args.archive, manifest["archive"], "archive")
            print("ISCX evidence: PASS " + json.dumps(summary, ensure_ascii=False, sort_keys=True))
        elif args.command == "prepare":
            result = prepare(args)
            print(args.work_root / "prepared.json", len(result["folds"]), "folds")
        else:
            train(args)
            print(args.output)
        return 0
    except (EvidenceError, OSError, KeyError, TypeError) as exc:
        print(f"iscx-reproduction: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

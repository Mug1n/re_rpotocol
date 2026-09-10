#!/usr/bin/env python3
"""M10: deterministic, non-semantic behaviour observations from verified M09."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1"
M09_SCHEMA = ROOT / "research" / "M09-flow-features" / "flow-features.schema.json"
OUTPUT_SCHEMA = ROOT / "research" / "M10-behavior-analysis" / "behaviors.schema.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_reference(input_path: Path, value: str) -> Path:
    recorded = Path(value)
    candidates = [recorded]
    if not recorded.is_absolute():
        candidates.append(input_path.parent / recorded)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"declared upstream artifact does not exist: {value}")


def load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid M09 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("M09 artifact root must be an object")
    jsonschema.validate(value, json.loads(M09_SCHEMA.read_text(encoding="utf-8")))
    source = value["source"]
    upstream = _resolve_reference(path, source["artifact_path"])
    if digest(upstream) != source["artifact_sha256"]:
        raise ValueError("M09 declared M01 artifact SHA-256 mismatch")
    return value, hashlib.sha256(raw).hexdigest()


def observation(
    flow: dict[str, Any], kind: str, values: dict[str, Any],
    thresholds: dict[str, Any], limitations: list[str],
) -> dict[str, Any]:
    return {
        "behavior_id": f"{flow['flow_id']}:{kind}", "flow_id": flow["flow_id"],
        "type": kind, "observed_values": values, "thresholds": thresholds,
        "evidence_refs": [{"record_id": flow["flow_id"],
                           "feature_definition_version": VERSION}],
        "confidence_basis": "deterministic threshold rule", "limitations": limitations,
    }


def _validate_parameters(
    dominance: float, periodic_cv: float, minimum_iats: int, burst_packets: int,
    long_seconds: float, idle_seconds: float,
) -> None:
    numbers = (dominance, periodic_cv, long_seconds, idle_seconds)
    if any(isinstance(value, bool) or not math.isfinite(value) for value in numbers):
        raise ValueError("M10 numeric thresholds must be finite")
    if not 0.5 <= dominance <= 1:
        raise ValueError("dominance must be between 0.5 and 1")
    if periodic_cv < 0 or long_seconds < 0 or idle_seconds < 0:
        raise ValueError("M10 time and variation thresholds must be non-negative")
    if isinstance(minimum_iats, bool) or minimum_iats <= 0:
        raise ValueError("minimum_iats must be a positive integer")
    if isinstance(burst_packets, bool) or burst_packets <= 0:
        raise ValueError("burst_packets must be a positive integer")


def _publish(destination: Path, result: dict[str, Any]) -> dict[str, Any]:
    jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "behaviors.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def analyze(
    input_path: Path, output_dir: Path, *, dominance: float = 0.8,
    periodic_cv: float = 0.1, minimum_iats: int = 3, burst_packets: int = 3,
    long_seconds: float = 60.0, idle_seconds: float = 10.0,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    _validate_parameters(dominance, periodic_cv, minimum_iats, burst_packets,
                         long_seconds, idle_seconds)
    source, source_sha256 = load(input_path)
    rules = {
        "version": VERSION, "direction_dominance_ratio": dominance,
        "periodicity_max_iat_cv": periodic_cv, "periodicity_min_iats": minimum_iats,
        "bursty_min_packets": burst_packets, "long_lived_min_seconds": long_seconds,
        "intermittent_idle_min_seconds": idle_seconds,
    }
    result: dict[str, Any] = {
        "schema_version": VERSION,
        "source": {"module": "M09", "artifact_path": str(input_path),
                   "artifact_sha256": source_sha256, "record_count": len(source["flows"]),
                   "schema_version": source["schema_version"]},
        "status": "ok", "parameters": rules, "rule_set": dict(rules),
        "metrics": {"flow_count": len(source["flows"]), "observation_count": 0},
        "observations": [], "insufficient_scopes": [], "warnings": [],
    }
    unavailable_by_flow: dict[str, set[str]] = {}
    for item in source["unavailable_features"]:
        unavailable_by_flow.setdefault(item["flow_id"], set()).add(item["feature"])
    for flow in sorted(source["flows"], key=lambda item: item["flow_id"]):
        flow_id = flow["flow_id"]
        unavailable = unavailable_by_flow.get(flow_id, set())
        ratio = flow["node0_to_node1_byte_ratio"]
        if ratio is not None and "directional_statistics" not in unavailable:
            if max(ratio, 1 - ratio) >= dominance:
                result["observations"].append(observation(
                    flow, "direction_dominance", {"node0_to_node1_byte_ratio": ratio},
                    {"minimum_dominant_ratio": dominance},
                    ["Directions are node-relative, not client/server roles."]))
        else:
            result["insufficient_scopes"].append(
                {"flow_id": flow_id, "rule": "direction_dominance",
                 "reason_code": "directional_bytes_unavailable"})

        if "duration_iat_rate_burst" in unavailable:
            for rule in ("periodicity_candidate", "bursty_transfer",
                         "long_lived_intermittent"):
                result["insufficient_scopes"].append(
                    {"flow_id": flow_id, "rule": rule,
                     "reason_code": "timestamp_missing_or_invalid"})
            continue
        interarrival = flow["packet_interarrival_seconds"]
        coefficient = flow["interarrival_cv"]
        if interarrival["count"] >= minimum_iats and coefficient is not None \
                and coefficient <= periodic_cv:
            result["observations"].append(observation(
                flow, "periodicity_candidate",
                {"iat_count": interarrival["count"], "iat_cv": coefficient,
                 "mean_iat_seconds": interarrival["mean"]},
                {"min_iats": minimum_iats, "max_iat_cv": periodic_cv},
                ["Statistical regularity is not an application or intent label."]))
        if flow["burst"]["max_packets"] is not None \
                and flow["burst"]["max_packets"] >= burst_packets:
            result["observations"].append(observation(
                flow, "bursty_transfer", {"max_burst_packets": flow["burst"]["max_packets"]},
                {"min_burst_packets": burst_packets}, ["Bursting is a traffic pattern only."]))
        duration, idle = flow["duration_seconds"], interarrival["max"]
        if duration is not None and idle is not None \
                and duration >= long_seconds and idle >= idle_seconds:
            result["observations"].append(observation(
                flow, "long_lived_intermittent",
                {"duration_seconds": duration, "max_iat_seconds": idle},
                {"min_duration_seconds": long_seconds, "min_idle_seconds": idle_seconds},
                ["No endpoint role or application identity was inferred."]))
    if not source["flows"]:
        result["status"] = "empty"
    elif result["insufficient_scopes"]:
        result["status"] = "partial" if result["observations"] else "insufficient_evidence"
    result["metrics"]["observation_count"] = len(result["observations"])
    return _publish(output_dir, result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Derive non-semantic M10 traffic-pattern observations.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--dominance", type=float, default=0.8)
    parser.add_argument("--periodic-cv", type=float, default=0.1)
    parser.add_argument("--minimum-iats", type=int, default=3)
    parser.add_argument("--burst-packets", type=int, default=3)
    parser.add_argument("--long-seconds", type=float, default=60.0)
    parser.add_argument("--idle-seconds", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze(args.input, args.output_dir, dominance=args.dominance,
                periodic_cv=args.periodic_cv, minimum_iats=args.minimum_iats,
                burst_packets=args.burst_packets, long_seconds=args.long_seconds,
                idle_seconds=args.idle_seconds)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m10: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "behaviors.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

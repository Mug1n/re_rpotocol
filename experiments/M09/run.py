#!/usr/bin/env python3
"""M09: derive conservative flow features from a verified M01 artifact."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import median
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import (  # noqa: E402
    load_json_artifact_with_sha256,
    validate_m01_references,
)

SCHEMA_VERSION = "0.1"
M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
OUTPUT_SCHEMA = ROOT / "research" / "M09-flow-features" / "flow-features.schema.json"


def finite(value: float | None) -> float | None:
    return value if value is None or math.isfinite(value) else None


def summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "min": None, "max": None, "mean": None,
                "median": None, "p95": None, "sum": 0.0}
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "count": len(values), "min": finite(min(values)), "max": finite(max(values)),
        "mean": finite(sum(values) / len(values)), "median": finite(float(median(values))),
        "p95": finite(ordered[index]), "sum": finite(sum(values)),
    }


def timestamp(packet: dict[str, Any]) -> Decimal | None:
    value = packet.get("timestamp_epoch")
    if value is None:
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return parsed if parsed.is_finite() else None


def packet_direction(packet: dict[str, Any], flow: dict[str, Any]) -> str | None:
    node0, node1 = flow["node0"], flow["node1"]
    source = (packet["src_ip"], packet["src_port"])
    destination = (packet["dst_ip"], packet["dst_port"])
    first = (node0["ip"], node0["port"])
    second = (node1["ip"], node1["port"])
    if source == first and destination == second:
        return "node0_to_node1"
    if source == second and destination == first:
        return "node1_to_node0"
    return None


def build_flow(
    flow: dict[str, Any], packet_by_id: dict[str, dict[str, Any]], *,
    retransmission_policy: str, burst_gap_seconds: float,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    missing: list[dict[str, str]] = []
    packets = [packet_by_id[item] for item in flow["packet_ids"]]
    packets.sort(key=lambda item: item["index"])
    selected = [packet for packet in packets if retransmission_policy == "include"
                or not packet["analysis"]["retransmission"]]
    lengths = [float(packet["captured_length"]) for packet in selected
               if packet["captured_length"] is not None]
    if len(lengths) != len(selected):
        missing.append({"feature": "packet_length_statistics",
                        "reason_code": "captured_length_missing"})

    directional_packets: dict[str, list[dict[str, Any]]] = {
        "node0_to_node1": [], "node1_to_node0": []}
    directions = []
    for packet in selected:
        direction = packet_direction(packet, flow)
        directions.append(direction)
        if direction is not None:
            directional_packets[direction].append(packet)
    if any(direction is None for direction in directions):
        missing.append({"feature": "directional_statistics",
                        "reason_code": "endpoint_mapping_missing"})

    dated = [(timestamp(packet), packet) for packet in selected]
    if any(item[0] is None for item in dated):
        missing.append({"feature": "duration_iat_rate_burst",
                        "reason_code": "timestamp_missing_or_invalid"})
        duration = None
        interarrivals: list[float] = []
        bursts: list[int] = []
    else:
        dated.sort(key=lambda item: item[0])
        times = [item[0] for item in dated]
        duration = float(times[-1] - times[0]) if len(times) > 1 else 0.0
        interarrivals = [float(times[index] - times[index - 1])
                         for index in range(1, len(times))]
        if any(value < 0 for value in interarrivals):
            raise ValueError(f"flow {flow['id']} has decreasing packet timestamps")
        bursts = []
        current = 1 if times else 0
        for interval in interarrivals:
            if interval <= burst_gap_seconds:
                current += 1
            else:
                bursts.append(current)
                current = 1
        if current:
            bursts.append(current)

    directional: dict[str, Any] = {}
    for direction, items in directional_packets.items():
        values = [float(packet["captured_length"]) for packet in items
                  if packet["captured_length"] is not None]
        directional[direction] = {
            "packet_count": len(items), "bytes": int(sum(values)), "length": summary(values)}
    total_bytes = int(sum(lengths))
    ratio = directional["node0_to_node1"]["bytes"] / total_bytes if total_bytes else None
    interarrival_summary = summary(interarrivals)
    mean_interarrival = interarrival_summary["mean"]
    coefficient_of_variation = None
    if interarrivals and isinstance(mean_interarrival, (int, float)) and mean_interarrival > 0:
        variance = sum((value - mean_interarrival) ** 2 for value in interarrivals) / len(interarrivals)
        coefficient_of_variation = math.sqrt(variance) / mean_interarrival

    record = {
        "flow_id": flow["id"], "packet_ids": [packet["id"] for packet in selected],
        "packet_count": len(selected), "byte_count": total_bytes,
        "directional": directional, "packet_length": summary(lengths),
        "duration_seconds": duration, "packet_interarrival_seconds": interarrival_summary,
        "interarrival_cv": finite(coefficient_of_variation),
        "rate_bytes_per_second": finite(total_bytes / duration)
        if duration is not None and duration > 0 else None,
        "direction_switches": sum(left is not None and right is not None and left != right
                                  for left, right in zip(directions, directions[1:])),
        "node0_to_node1_byte_ratio": finite(ratio),
        "burst": {"gap_seconds": burst_gap_seconds, "count": len(bursts),
                  "max_packets": max(bursts) if bursts else None},
        "integrity": {
            "truncated_packets": sum(bool(packet["truncated"]) for packet in selected),
            "retransmission_packets": sum(bool(packet["analysis"]["retransmission"])
                                           for packet in packets),
            "out_of_order_packets": sum(bool(packet["analysis"]["out_of_order"])
                                          for packet in packets),
            "gap_or_loss_packets": sum(bool(packet["analysis"]["gap_or_loss"])
                                         for packet in packets),
        },
    }
    return record, missing


def _publish(destination: Path, result: dict[str, Any]) -> dict[str, Any]:
    jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "flow_features.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def analyze(
    input_path: Path, output_dir: Path, *, retransmission_policy: str = "include",
    burst_gap_seconds: float = 1.0,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    if retransmission_policy not in {"include", "exclude"}:
        raise ValueError("retransmission_policy must be include or exclude")
    if not math.isfinite(burst_gap_seconds) or burst_gap_seconds < 0:
        raise ValueError("burst_gap_seconds must be finite and non-negative")
    source, source_sha256 = load_json_artifact_with_sha256(input_path)
    jsonschema.validate(source, json.loads(M01_SCHEMA.read_text(encoding="utf-8")))
    validate_m01_references(source)
    packet_by_id = {packet["id"]: packet for packet in source["packets"]}
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": {"module": "M01", "artifact_path": str(input_path),
                   "artifact_sha256": source_sha256, "record_count": len(source["flows"]),
                   "schema_version": source["schema_version"]},
        "status": "ok",
        "parameters": {"retransmission_policy": retransmission_policy,
                       "burst_gap_seconds": burst_gap_seconds,
                       "length_basis": "captured_length",
                       "direction_role_mapping": "node_relative",
                       "quantile_method": "nearest_rank"},
        "feature_definition": {"version": SCHEMA_VERSION, "time_unit": "seconds",
                               "byte_range": "captured packet length",
                               "direction": "node_relative"},
        "metrics": {"flow_count": 0, "packet_count": 0},
        "flows": [], "unavailable_features": [], "warnings": [],
    }
    if not source["flows"]:
        result["status"] = "insufficient_metadata" if not source["packets"] else "empty"
        result["warnings"].append(
            "No M01 flow records are available; no network-flow features were inferred.")
    for flow in sorted(source["flows"], key=lambda item: item["id"]):
        feature, unavailable = build_flow(
            flow, packet_by_id, retransmission_policy=retransmission_policy,
            burst_gap_seconds=burst_gap_seconds)
        result["flows"].append(feature)
        result["unavailable_features"].extend(
            {"flow_id": feature["flow_id"], **item} for item in unavailable)
    result["metrics"] = {"flow_count": len(result["flows"]),
                         "packet_count": sum(item["packet_count"] for item in result["flows"])}
    if result["flows"] and result["unavailable_features"]:
        result["status"] = "partial"
    return _publish(output_dir, result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute conservative M09 flow features from M01 JSON.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--retransmission-policy", choices=("include", "exclude"), default="include")
    parser.add_argument("--burst-gap-seconds", type=float, default=1.0)
    args = parser.parse_args(argv)
    try:
        analyze(args.input, args.output_dir, retransmission_policy=args.retransmission_policy,
                burst_gap_seconds=args.burst_gap_seconds)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m09: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "flow_features.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

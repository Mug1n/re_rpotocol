#!/usr/bin/env python3
"""M09: derive conservative flow features from a verified M01 artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import median
from typing import Any


SCHEMA_VERSION = "0.1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON artifact root must be an object")
    return value


def finite(value: float | None) -> float | None:
    return value if value is None or math.isfinite(value) else None


def summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None,
                "p95": None, "sum": 0.0}
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
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def packet_direction(packet: dict[str, Any], flow: dict[str, Any]) -> str | None:
    node0, node1 = flow.get("node0", {}), flow.get("node1", {})
    src = (packet.get("src_ip"), packet.get("src_port"))
    dst = (packet.get("dst_ip"), packet.get("dst_port"))
    first = (node0.get("ip"), node0.get("port"))
    second = (node1.get("ip"), node1.get("port"))
    if src == first and dst == second:
        return "node0_to_node1"
    if src == second and dst == first:
        return "node1_to_node0"
    return None


def build_flow(flow: dict[str, Any], packet_by_id: dict[str, dict[str, Any]], *,
               retransmission_policy: str, burst_gap_seconds: float) -> tuple[dict[str, Any], list[dict[str, str]]]:
    missing: list[dict[str, str]] = []
    packets = [packet_by_id[item] for item in flow.get("packet_ids", []) if item in packet_by_id]
    packets.sort(key=lambda item: item.get("index", 0))
    if len(packets) != len(flow.get("packet_ids", [])):
        missing.append({"feature": "all", "reason_code": "missing_packet_reference"})
    selected = [p for p in packets if retransmission_policy == "include" or not p.get("analysis", {}).get("retransmission", False)]
    lengths = [float(p["captured_length"]) for p in selected if isinstance(p.get("captured_length"), (int, float))]
    if len(lengths) != len(selected):
        missing.append({"feature": "packet_length_statistics", "reason_code": "captured_length_missing"})
    dirs = {"node0_to_node1": [], "node1_to_node0": []}
    unknown_direction = 0
    for packet in selected:
        direction = packet_direction(packet, flow)
        if direction is None:
            unknown_direction += 1
        else:
            dirs[direction].append(packet)
    if unknown_direction:
        missing.append({"feature": "directional_statistics", "reason_code": "endpoint_mapping_missing"})
    dated = [(timestamp(p), p) for p in selected]
    if any(item[0] is None for item in dated):
        missing.append({"feature": "duration_iat_rate_burst", "reason_code": "timestamp_missing_or_invalid"})
        duration = None
        iats: list[float] = []
        bursts: list[int] = []
    else:
        dated.sort(key=lambda item: item[0])
        times = [item[0] for item in dated if item[0] is not None]
        duration = float(times[-1] - times[0]) if len(times) > 1 else 0.0
        iats = [float(times[i] - times[i - 1]) for i in range(1, len(times))]
        bursts, current = [], 1 if times else 0
        for interval in iats:
            if interval <= burst_gap_seconds:
                current += 1
            else:
                bursts.append(current)
                current = 1
        if current:
            bursts.append(current)
    directional = {}
    for direction, items in dirs.items():
        dlengths = [float(p["captured_length"]) for p in items if isinstance(p.get("captured_length"), (int, float))]
        directional[direction] = {"packet_count": len(items), "bytes": int(sum(dlengths)), "length": summary(dlengths)}
    total_bytes = int(sum(lengths))
    count = len(selected)
    ratio0 = (directional["node0_to_node1"]["bytes"] / total_bytes) if total_bytes else None
    iat_summary = summary(iats)
    mean_iat = iat_summary["mean"]
    cv = None
    if iats and mean_iat and mean_iat > 0:
        variance = sum((value - mean_iat) ** 2 for value in iats) / len(iats)
        cv = math.sqrt(variance) / mean_iat
    record = {
        "flow_id": flow.get("id"), "packet_ids": [p.get("id") for p in selected],
        "packet_count": count, "byte_count": total_bytes, "directional": directional,
        "packet_length": summary(lengths), "duration_seconds": duration,
        "packet_interarrival_seconds": iat_summary, "interarrival_cv": finite(cv),
        "rate_bytes_per_second": finite(total_bytes / duration) if duration and duration > 0 else None,
        "direction_switches": sum(1 for a, b in zip([packet_direction(p, flow) for p in selected], [packet_direction(p, flow) for p in selected][1:]) if a and b and a != b),
        "node0_to_node1_byte_ratio": finite(ratio0),
        "burst": {"gap_seconds": burst_gap_seconds, "count": len(bursts), "max_packets": max(bursts) if bursts else None},
        "integrity": {"truncated_packets": sum(bool(p.get("truncated")) for p in selected),
                      "retransmission_packets": sum(bool(p.get("analysis", {}).get("retransmission")) for p in packets),
                      "out_of_order_packets": sum(bool(p.get("analysis", {}).get("out_of_order")) for p in packets),
                      "gap_or_loss_packets": sum(bool(p.get("analysis", {}).get("gap_or_loss")) for p in packets)},
    }
    return record, missing


def analyze(input_path: Path, output_dir: Path, *, retransmission_policy: str = "include", burst_gap_seconds: float = 1.0) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    source = read_json(input_path)
    if source.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported M01 schema_version")
    packets = source.get("packets")
    flows = source.get("flows")
    if not isinstance(packets, list) or not isinstance(flows, list):
        raise ValueError("M01 artifact must contain packets and flows arrays")
    packet_by_id = {packet.get("id"): packet for packet in packets if isinstance(packet, dict) and isinstance(packet.get("id"), str)}
    result: dict[str, Any] = {"schema_version": SCHEMA_VERSION,
        "source": {"module": "M01", "artifact_path": str(input_path), "artifact_sha256": sha256(input_path), "record_count": len(flows)},
        "status": "ok", "parameters": {"retransmission_policy": retransmission_policy, "burst_gap_seconds": burst_gap_seconds, "length_basis": "captured_length", "direction_role_mapping": "node_relative", "quantile_method": "nearest_rank"},
        "feature_definition": {"version": SCHEMA_VERSION, "time_unit": "seconds", "byte_range": "captured packet length", "direction": "node_relative"},
        "metrics": {"flow_count": 0, "packet_count": 0}, "flows": [], "unavailable_features": [], "warnings": []}
    if not flows:
        result["status"] = "insufficient_metadata" if not packets else "empty"
        result["warnings"].append("No M01 flow records are available; no network-flow features were inferred.")
    for flow in sorted((item for item in flows if isinstance(item, dict)), key=lambda item: str(item.get("id", ""))):
        feature, unavailable = build_flow(flow, packet_by_id, retransmission_policy=retransmission_policy, burst_gap_seconds=burst_gap_seconds)
        result["flows"].append(feature)
        for item in unavailable:
            result["unavailable_features"].append({"flow_id": feature["flow_id"], **item})
    result["metrics"] = {"flow_count": len(result["flows"]), "packet_count": sum(item["packet_count"] for item in result["flows"])}
    if result["flows"] and result["unavailable_features"]:
        result["status"] = "partial"
    output_dir.mkdir(parents=True)
    (output_dir / "flow_features.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute conservative M09 flow features from M01 JSON.")
    parser.add_argument("input", type=Path); parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--retransmission-policy", choices=("include", "exclude"), default="include")
    parser.add_argument("--burst-gap-seconds", type=float, default=1.0)
    args = parser.parse_args(argv)
    try:
        if args.burst_gap_seconds < 0: raise ValueError("burst gap must be non-negative")
        analyze(args.input, args.output_dir, retransmission_policy=args.retransmission_policy, burst_gap_seconds=args.burst_gap_seconds)
    except (ValueError, FileExistsError, OSError) as exc:
        print(f"m09: {exc}", file=__import__("sys").stderr); return 2
    print(args.output_dir / "flow_features.json"); return 0


if __name__ == "__main__": raise SystemExit(main())


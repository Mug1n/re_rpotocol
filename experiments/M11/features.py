"""Deterministic, non-redundant feature initialization for M11 behavior classification.

Derives a fixed-dimension numeric feature vector from one M09 flow record. The
vector deliberately avoids pure derivations (e.g. rate = bytes / duration) and
normalizes raw counts into ratios so the classifier sees independent signals
rather than collinear ones. Kept separate from ``build_rows.py`` so the feature
definition can be unit-tested in isolation and versioned independently.
"""

from __future__ import annotations

import math
from typing import Any

FEATURE_SET_VERSION = "0.2"

# Ordered, fixed feature names. Keep in sync with FEATURE_SET_VERSION.
FEATURE_NAMES: tuple[str, ...] = (
    # volume & size
    "packet_count",
    "byte_count",
    "packet_length_mean",
    "packet_length_p95",
    "packet_length_median",
    # direction & asymmetry
    "node0_to_node1_packet_ratio",
    "node0_to_node1_byte_ratio",
    "direction_switches_per_packet",
    # timing
    "duration_seconds",
    "iat_mean",
    "iat_p95",
    "iat_cv",
    # burst structure
    "burst_count",
    "burst_avg_packets",
    "burst_max_packets",
    # integrity / quality
    "retransmission_ratio",
    "gap_or_loss_ratio",
)


def _number(value: Any, name: str, missing: list[str]) -> float | None:
    """Return a finite float for ``value`` or record ``name`` as missing."""
    if value is None:
        missing.append(name)
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        missing.append(name)
        return None
    if not math.isfinite(number):
        missing.append(name)
        return None
    return number


def build_features(flow: dict[str, Any]) -> tuple[dict[str, float] | None, list[str]]:
    """Derive the fixed M11 feature vector from one M09 flow record.

    Returns ``(features, missing)``. ``features`` is ``None`` when a required
    upstream value is absent; ``missing`` names the offending fields so the
    caller can record the skip instead of fabricating a value. Otherwise it is a
    dict keyed by :data:`FEATURE_NAMES` with finite floats only.
    """
    missing: list[str] = []

    packet_count = _number(flow.get("packet_count"), "packet_count", missing)
    if packet_count is None:
        return None, missing
    if packet_count <= 0:
        return None, ["packet_count_zero"]

    byte_count = _number(flow.get("byte_count"), "byte_count", missing)

    packet_length = flow.get("packet_length") or {}
    packet_length_mean = _number(packet_length.get("mean"), "packet_length_mean", missing)
    packet_length_p95 = _number(packet_length.get("p95"), "packet_length_p95", missing)
    packet_length_median = _number(packet_length.get("median"), "packet_length_median", missing)

    directional = flow.get("directional") or {}
    node0_to_node1 = directional.get("node0_to_node1") or {}
    node0_to_node1_packets = _number(
        node0_to_node1.get("packet_count"), "node0_to_node1_packet_count", missing)
    node0_to_node1_packet_ratio = (
        node0_to_node1_packets / packet_count if node0_to_node1_packets is not None else None)
    node0_to_node1_byte_ratio = _number(
        flow.get("node0_to_node1_byte_ratio"), "node0_to_node1_byte_ratio", missing)

    direction_switches = _number(flow.get("direction_switches"), "direction_switches", missing)
    direction_switches_per_packet = (
        direction_switches / max(packet_count - 1.0, 1.0) if direction_switches is not None else None)

    duration_seconds = _number(flow.get("duration_seconds"), "duration_seconds", missing)
    interarrival = flow.get("packet_interarrival_seconds") or {}
    iat_mean = _number(interarrival.get("mean"), "iat_mean", missing)
    iat_p95 = _number(interarrival.get("p95"), "iat_p95", missing)
    iat_cv = _number(flow.get("interarrival_cv"), "iat_cv", missing)

    burst = flow.get("burst") or {}
    burst_count = _number(burst.get("count"), "burst_count", missing)
    burst_max_packets = _number(burst.get("max_packets"), "burst_max_packets", missing)
    if burst_count is not None and burst_count > 0:
        burst_avg_packets = packet_count / burst_count
    elif burst_count is not None:
        burst_avg_packets = None
        missing.append("burst_avg_packets")
    else:
        burst_avg_packets = None

    integrity = flow.get("integrity") or {}
    retransmissions = _number(integrity.get("retransmission_packets"), "retransmission_packets", missing)
    gaps = _number(integrity.get("gap_or_loss_packets"), "gap_or_loss_packets", missing)
    retransmission_ratio = retransmissions / packet_count if retransmissions is not None else None
    gap_or_loss_ratio = gaps / packet_count if gaps is not None else None

    features = {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packet_length_mean": packet_length_mean,
        "packet_length_p95": packet_length_p95,
        "packet_length_median": packet_length_median,
        "node0_to_node1_packet_ratio": node0_to_node1_packet_ratio,
        "node0_to_node1_byte_ratio": node0_to_node1_byte_ratio,
        "direction_switches_per_packet": direction_switches_per_packet,
        "duration_seconds": duration_seconds,
        "iat_mean": iat_mean,
        "iat_p95": iat_p95,
        "iat_cv": iat_cv,
        "burst_count": burst_count,
        "burst_avg_packets": burst_avg_packets,
        "burst_max_packets": burst_max_packets,
        "retransmission_ratio": retransmission_ratio,
        "gap_or_loss_ratio": gap_or_loss_ratio,
    }

    if missing:
        return None, missing
    if list(features) != list(FEATURE_NAMES):
        raise AssertionError("feature vector does not match FEATURE_NAMES")
    return features, []

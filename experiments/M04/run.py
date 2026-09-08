#!/usr/bin/env python3
"""M4 explainable message clustering with a dependency-free DBSCAN baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import sys
import tempfile
from collections import Counter, deque
from pathlib import Path
from typing import Any, Hashable, Iterable


SCHEMA_VERSION = "0.1"
NOISE = -1
UNASSIGNED = -2


def _histogram(data: bytes) -> tuple[float, ...]:
    if not data:
        return (0.0,) * 256
    counts = Counter(data)
    length = len(data)
    return tuple(counts.get(value, 0) / length for value in range(256))


def _features(data: bytes) -> dict[str, Any]:
    return {"length": len(data), "histogram": _histogram(data), "prefix": data}


def message_distance(
    left: bytes,
    right: bytes,
    *,
    length_weight: float = 0.2,
    histogram_weight: float = 0.4,
    prefix_weight: float = 0.4,
    prefix_length: int = 16,
) -> tuple[float, dict[str, float]]:
    weights = (length_weight, histogram_weight, prefix_weight)
    if any(weight < 0 for weight in weights) or sum(weights) <= 0:
        raise ValueError("distance weights must be non-negative with a positive sum")
    if prefix_length < 0:
        raise ValueError("prefix_length must be non-negative")
    left_features = _features(left)
    right_features = _features(right)
    denominator = max(len(left), len(right), 1)
    length_distance = abs(len(left) - len(right)) / denominator
    histogram_distance = sum(
        abs(a - b)
        for a, b in zip(left_features["histogram"], right_features["histogram"])
    ) / 2
    compared = min(prefix_length, max(len(left), len(right)))
    if compared:
        mismatches = sum(
            index >= len(left)
            or index >= len(right)
            or left[index] != right[index]
            for index in range(compared)
        )
        prefix_distance = mismatches / compared
    else:
        prefix_distance = 0.0
    total_weight = sum(weights)
    distance = (
        length_weight * length_distance
        + histogram_weight * histogram_distance
        + prefix_weight * prefix_distance
    ) / total_weight
    return distance, {
        "length": length_distance,
        "histogram": histogram_distance,
        "prefix": prefix_distance,
    }


def build_distance_matrix(
    messages: list[bytes],
    **distance_parameters: Any,
) -> list[list[float]]:
    matrix = [[0.0] * len(messages) for _ in messages]
    for left in range(len(messages)):
        for right in range(left + 1, len(messages)):
            distance, _ = message_distance(
                messages[left], messages[right], **distance_parameters
            )
            matrix[left][right] = distance
            matrix[right][left] = distance
    return matrix


def dbscan(
    distances: list[list[float]],
    *,
    eps: float,
    min_samples: int,
) -> list[int]:
    count = len(distances)
    if eps < 0 or eps > 1:
        raise ValueError("eps must be between 0 and 1")
    if min_samples <= 0:
        raise ValueError("min_samples must be positive")
    if any(len(row) != count for row in distances):
        raise ValueError("distance matrix must be square")
    labels = [UNASSIGNED] * count
    visited = [False] * count
    cluster_id = 0

    def neighbors(index: int) -> list[int]:
        return [other for other, value in enumerate(distances[index]) if value <= eps]

    for point in range(count):
        if visited[point]:
            continue
        visited[point] = True
        seeds = neighbors(point)
        if len(seeds) < min_samples:
            labels[point] = NOISE
            continue
        labels[point] = cluster_id
        queue = deque(seeds)
        queued = set(seeds)
        while queue:
            candidate = queue.popleft()
            if not visited[candidate]:
                visited[candidate] = True
                candidate_neighbors = neighbors(candidate)
                if len(candidate_neighbors) >= min_samples:
                    for neighbor in candidate_neighbors:
                        if neighbor not in queued:
                            queued.add(neighbor)
                            queue.append(neighbor)
            if labels[candidate] in (UNASSIGNED, NOISE):
                labels[candidate] = cluster_id
        cluster_id += 1
    return labels


def _representative(indices: list[int], distances: list[list[float]]) -> int:
    return min(indices, key=lambda index: (sum(distances[index][other] for other in indices), index))


def silhouette_score(distances: list[list[float]], labels: list[int]) -> float | None:
    clustered = [index for index, label in enumerate(labels) if label != NOISE]
    cluster_ids = sorted(set(labels[index] for index in clustered))
    if len(cluster_ids) < 2:
        return None
    members = {label: [index for index in clustered if labels[index] == label] for label in cluster_ids}
    values: list[float] = []
    for index in clustered:
        own = members[labels[index]]
        if len(own) == 1:
            values.append(0.0)
            continue
        within = sum(distances[index][other] for other in own if other != index) / (len(own) - 1)
        nearest = min(
            sum(distances[index][other] for other in members[label]) / len(members[label])
            for label in cluster_ids
            if label != labels[index]
        )
        scale = max(within, nearest)
        values.append((nearest - within) / scale if scale else 0.0)
    return sum(values) / len(values) if values else None


def _comb2(value: int) -> int:
    return value * (value - 1) // 2


def adjusted_rand_index(truth: Iterable[Hashable], predicted: Iterable[Hashable]) -> float:
    truth_list = list(truth)
    predicted_list = list(predicted)
    if len(truth_list) != len(predicted_list):
        raise ValueError("truth and predicted labels must have equal length")
    size = len(truth_list)
    if size < 2:
        return 1.0
    truth_counts = Counter(truth_list)
    predicted_counts = Counter(predicted_list)
    contingency = Counter(zip(truth_list, predicted_list))
    index = sum(_comb2(value) for value in contingency.values())
    truth_pairs = sum(_comb2(value) for value in truth_counts.values())
    predicted_pairs = sum(_comb2(value) for value in predicted_counts.values())
    total_pairs = _comb2(size)
    expected = truth_pairs * predicted_pairs / total_pairs
    maximum = (truth_pairs + predicted_pairs) / 2
    denominator = maximum - expected
    if denominator == 0:
        return 1.0 if index == maximum else 0.0
    return (index - expected) / denominator


def normalized_mutual_information(
    truth: Iterable[Hashable], predicted: Iterable[Hashable]
) -> float:
    truth_list = list(truth)
    predicted_list = list(predicted)
    if len(truth_list) != len(predicted_list):
        raise ValueError("truth and predicted labels must have equal length")
    size = len(truth_list)
    if size == 0:
        return 1.0
    truth_counts = Counter(truth_list)
    predicted_counts = Counter(predicted_list)
    contingency = Counter(zip(truth_list, predicted_list))
    mutual_information = sum(
        (count / size)
        * math.log((size * count) / (truth_counts[left] * predicted_counts[right]))
        for (left, right), count in contingency.items()
    )
    truth_entropy = -sum(
        (count / size) * math.log(count / size) for count in truth_counts.values()
    )
    predicted_entropy = -sum(
        (count / size) * math.log(count / size) for count in predicted_counts.values()
    )
    denominator = math.sqrt(truth_entropy * predicted_entropy)
    if denominator == 0:
        return 1.0 if truth_entropy == 0 and predicted_entropy == 0 else 0.0
    return mutual_information / denominator


def cluster_messages(
    message_items: list[tuple[str, bytes]],
    *,
    eps: float = 0.25,
    min_samples: int = 2,
    length_weight: float = 0.2,
    histogram_weight: float = 0.4,
    prefix_weight: float = 0.4,
    prefix_length: int = 16,
    max_messages: int = 1000,
    truth_labels: dict[str, Hashable] | None = None,
) -> dict[str, Any]:
    if len(message_items) > max_messages:
        raise ValueError(
            f"message count {len(message_items)} exceeds O(n^2) safety limit {max_messages}"
        )
    identifiers = [item[0] for item in message_items]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("message ids must be unique")
    payloads = [item[1] for item in message_items]
    distance_parameters = {
        "length_weight": length_weight,
        "histogram_weight": histogram_weight,
        "prefix_weight": prefix_weight,
        "prefix_length": prefix_length,
    }
    distances = build_distance_matrix(payloads, **distance_parameters)
    labels = dbscan(distances, eps=eps, min_samples=min_samples)
    cluster_ids = sorted(set(labels) - {NOISE})
    representatives: dict[int, int] = {}
    clusters: list[dict[str, Any]] = []
    for cluster_id in cluster_ids:
        indices = [index for index, label in enumerate(labels) if label == cluster_id]
        representative = _representative(indices, distances)
        representatives[cluster_id] = representative
        clusters.append(
            {
                "cluster_id": cluster_id,
                "size": len(indices),
                "message_ids": [identifiers[index] for index in indices],
                "representative_message_id": identifiers[representative],
                "mean_distance_to_representative": sum(
                    distances[index][representative] for index in indices
                )
                / len(indices),
            }
        )
    assignments = []
    for index, identifier in enumerate(identifiers):
        label = labels[index]
        representative = representatives.get(label)
        assignments.append(
            {
                "message_id": identifier,
                "length": len(payloads[index]),
                "cluster_id": label,
                "is_noise": label == NOISE,
                "distance_to_representative": (
                    distances[index][representative] if representative is not None else None
                ),
            }
        )
    metrics: dict[str, Any] = {
        "cluster_count": len(cluster_ids),
        "noise_count": labels.count(NOISE),
        "noise_ratio": labels.count(NOISE) / len(labels) if labels else 0.0,
        "silhouette": silhouette_score(distances, labels),
    }
    if truth_labels is not None:
        missing = [identifier for identifier in identifiers if identifier not in truth_labels]
        if missing:
            raise ValueError(f"truth labels missing message ids: {missing[:5]}")
        expected = [truth_labels[identifier] for identifier in identifiers]
        metrics["adjusted_rand_index"] = adjusted_rand_index(expected, labels)
        metrics["normalized_mutual_information"] = normalized_mutual_information(
            expected, labels
        )
        metrics["nmi_normalization"] = "geometric_mean"
    return {
        "parameters": {
            "algorithm": "dbscan_precomputed",
            "eps": eps,
            "min_samples": min_samples,
            "max_messages": max_messages,
            **distance_parameters,
            "distance_formula": "weighted normalized length + byte-histogram total variation + prefix mismatch",
        },
        "assignments": assignments,
        "clusters": clusters,
        "metrics": metrics,
    }


def _load_framed_messages(framing_path: Path) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    framing = json.loads(framing_path.read_text(encoding="utf-8"))
    base = framing_path.parent.resolve()
    items: list[tuple[str, bytes]] = []
    for message in framing.get("messages", []):
        reference = message.get("artifact_ref")
        if not reference:
            raise ValueError(f"message {message.get('id')} has no artifact_ref")
        artifact = (base / reference).resolve()
        try:
            artifact.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"artifact_ref escapes framing directory: {reference}") from exc
        data = artifact.read_bytes()
        if len(data) != message.get("length"):
            raise ValueError(f"message length mismatch for {message.get('id')}")
        items.append((str(message["id"]), data))
    return framing, items


def analyze_framing(
    framing_json: str | Path,
    output_dir: str | Path,
    *,
    truth_labels: dict[str, Hashable] | None = None,
    **parameters: Any,
) -> dict[str, Any]:
    source = Path(framing_json)
    if not source.is_file():
        raise FileNotFoundError(f"framing JSON does not exist: {source}")
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    framing, items = _load_framed_messages(source)
    clustered = cluster_messages(items, truth_labels=truth_labels, **parameters)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    result = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "framing_path": str(source),
            "framing_sha256": digest,
            "stream_id": framing.get("source", {}).get("id"),
            "message_count": len(items),
        },
        "status": "empty" if not items else "ok",
        **clustered,
        "warnings": [
            "Clusters are statistical groups, not protocol types or business labels.",
            "The precomputed distance matrix requires O(n^2) memory.",
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        (staging / "clusters.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cluster M03 messages with DBSCAN.")
    parser.add_argument("framing_json", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--eps", type=float, default=0.25)
    parser.add_argument("--min-samples", type=int, default=2)
    parser.add_argument("--length-weight", type=float, default=0.2)
    parser.add_argument("--histogram-weight", type=float, default=0.4)
    parser.add_argument("--prefix-weight", type=float, default=0.4)
    parser.add_argument("--prefix-length", type=int, default=16)
    parser.add_argument("--max-messages", type=int, default=1000)
    parser.add_argument("--truth-labels", type=Path, help="Optional JSON object: message_id -> label")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        truth = (
            json.loads(args.truth_labels.read_text(encoding="utf-8"))
            if args.truth_labels
            else None
        )
        analyze_framing(
            args.framing_json,
            args.output_dir,
            truth_labels=truth,
            eps=args.eps,
            min_samples=args.min_samples,
            length_weight=args.length_weight,
            histogram_weight=args.histogram_weight,
            prefix_weight=args.prefix_weight,
            prefix_length=args.prefix_length,
            max_messages=args.max_messages,
        )
    except (FileNotFoundError, FileExistsError, ValueError, json.JSONDecodeError) as exc:
        print(f"m04: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "clusters.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

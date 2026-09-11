#!/usr/bin/env python3
"""M6 explainable field-boundary and length-relation inference."""

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


SCHEMA_VERSION = "0.1"


def rank_framing_boundaries(framing: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return non-overlapping high-confidence boundaries implied by M03.

    This deliberately consumes only an already inferred framing hypothesis.  It
    does not name a protocol or inspect any external truth.  For a repeated
    payload-length relation, the length field itself, the payload start, and a
    fixed trailing overhead are much stronger evidence than a local entropy
    fluctuation inside an aligned payload.
    """
    selected = (framing or {}).get("parameters", {}).get("selected", {})
    if selected.get("length_mode") != "payload":
        return []
    try:
        offset = int(selected["length_offset"])
        width = int(selected["length_width"])
        overhead = int(selected["header_size"])
    except (KeyError, TypeError, ValueError):
        return []
    if offset < 0 or width not in (1, 2, 4, 8) or overhead < offset + width:
        return []
    candidates = [
        {"candidate_id": "framing-length-start", "position": {"reference": "start", "offset": offset},
         "confidence": 1.0, "evidence": "inferred_length_prefix"},
        {"candidate_id": "framing-payload-start", "position": {"reference": "start", "offset": offset + width},
         "confidence": 1.0, "evidence": "inferred_length_prefix"},
    ]
    trailing = overhead - (offset + width)
    if trailing:
        candidates.append(
            {"candidate_id": "framing-trailer-start", "position": {"reference": "end", "offset": trailing},
             "confidence": 0.95, "evidence": "inferred_fixed_overhead"}
        )
    return candidates


def _load_framing_from_alignments(source: Path, alignments: dict[str, Any]) -> dict[str, Any] | None:
    """Best-effort provenance walk M06 -> M05 -> M04 -> M03."""
    clusters_record = alignments.get("source", {}).get("clusters_path")
    if not isinstance(clusters_record, str):
        return None
    clusters_path = Path(clusters_record)
    candidates = [clusters_path, source.parent / clusters_path]
    for candidate in candidates:
        if candidate.is_file():
            clusters = json.loads(candidate.read_text(encoding="utf-8"))
            framing_record = clusters.get("source", {}).get("framing_path")
            if not isinstance(framing_record, str):
                return None
            framing_path = Path(framing_record)
            for framing_candidate in (framing_path, candidate.parent / framing_path):
                if framing_candidate.is_file():
                    return json.loads(framing_candidate.read_text(encoding="utf-8"))
    return None


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    size = len(values)
    value = -sum((count / size) * math.log2(count / size) for count in counts.values())
    return max(0.0, value)


def analyze_column(
    column: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    min_cluster_samples: int,
    min_presence_ratio: float,
) -> dict[str, Any]:
    index = int(column["column_index"])
    present = [row["cells"][index][1] for row in rows if row["cells"][index] is not None]
    counts = Counter(present)
    support = len(present)
    total = len(rows)
    presence_ratio = support / total if total else 0.0
    most_common = min(counts, key=lambda value: (-counts[value], value)) if counts else None
    if total < min_cluster_samples:
        classification = "insufficient_samples"
    elif presence_ratio < min_presence_ratio:
        classification = "sparse"
    elif len(counts) == 1 and support == total:
        classification = "fixed"
    elif len(counts) == 1:
        classification = "optional_fixed"
    elif support == total:
        classification = "variable"
    else:
        classification = "optional_variable"
    return {
        "column_index": index,
        "source_kind": column["kind"],
        "reference_offset": column["reference_offset"],
        "insertion_anchor": column["insertion_anchor"],
        "insertion_ordinal": column["insertion_ordinal"],
        "classification": classification,
        "sample_count": total,
        "support_count": support,
        "gap_count": total - support,
        "presence_ratio": presence_ratio,
        "distinct_value_count": len(counts),
        "entropy_bits": _entropy(present),
        "most_common_byte": most_common,
        "most_common_ratio": counts[most_common] / support if most_common is not None else None,
    }


def _segments(columns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not columns:
        return []
    groups: list[list[dict[str, Any]]] = [[columns[0]]]
    for column in columns[1:]:
        previous = groups[-1][-1]
        if (
            column["classification"] == previous["classification"]
            and column["source_kind"] == previous["source_kind"]
        ):
            groups[-1].append(column)
        else:
            groups.append([column])
    segments = []
    for index, group in enumerate(groups):
        reference_offsets = [
            column["reference_offset"]
            for column in group
            if column["reference_offset"] is not None
        ]
        reference_start = min(reference_offsets) if len(reference_offsets) == len(group) else None
        reference_end = max(reference_offsets) + 1 if len(reference_offsets) == len(group) else None
        segments.append(
            {
                "field_id": f"field-{index:04d}",
                "alignment_start": group[0]["column_index"],
                "alignment_end": group[-1]["column_index"] + 1,
                "width_columns": len(group),
                "source_kind": group[0]["source_kind"],
                "classification": group[0]["classification"],
                "reference_offset_start": reference_start,
                "reference_offset_end": reference_end,
                "min_presence_ratio": min(column["presence_ratio"] for column in group),
                "max_presence_ratio": max(column["presence_ratio"] for column in group),
                "mean_entropy_bits": sum(column["entropy_bits"] for column in group) / len(group),
                "max_entropy_bits": max(column["entropy_bits"] for column in group),
            }
        )
    return segments


def _boundaries(
    segments: list[dict[str, Any]], columns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    boundaries = []
    for left, right in zip(segments, segments[1:]):
        index = right["alignment_start"]
        reasons = []
        if left["classification"] != right["classification"]:
            reasons.append("column_class_change")
        if left["source_kind"] != right["source_kind"]:
            reasons.append("reference_insertion_transition")
        entropy_jump = abs(columns[index]["entropy_bits"] - columns[index - 1]["entropy_bits"])
        if entropy_jump > 0:
            reasons.append("entropy_change")
        boundaries.append(
            {
                "alignment_column": index,
                "left_field_id": left["field_id"],
                "right_field_id": right["field_id"],
                "reasons": reasons,
                "entropy_jump_bits": entropy_jump,
            }
        )
    return boundaries


def _candidate_windows(
    columns: list[dict[str, Any]], widths: tuple[int, ...]
) -> list[tuple[int, int]]:
    windows = []
    for start in range(len(columns)):
        for width in widths:
            end = start + width
            if end > len(columns):
                continue
            group = columns[start:end]
            offsets = [column["reference_offset"] for column in group]
            if (
                all(column["kind"] == "reference" for column in group)
                and offsets == list(range(offsets[0], offsets[0] + width))
            ):
                windows.append((start, width))
    return windows


def infer_length_relations(
    columns: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    length_widths: tuple[int, ...],
    min_relation_samples: int,
    max_length_overhead: int,
) -> list[dict[str, Any]]:
    if len(rows) < min_relation_samples:
        return []
    candidates = []
    for start, width in _candidate_windows(columns, length_widths):
        observations = []
        valid = True
        for row in rows:
            cells = row["cells"][start:start + width]
            if any(cell is None for cell in cells):
                valid = False
                break
            offsets = [cell[0] for cell in cells]
            if offsets != list(range(offsets[0], offsets[0] + width)):
                valid = False
                break
            raw = bytes(cell[1] for cell in cells)
            observations.append((row["message_id"], row["length"], offsets[0], raw))
        if not valid:
            continue
        message_lengths = {observation[1] for observation in observations}
        if len(message_lengths) < 2:
            continue
        endiannesses = ("little",) if width == 1 else ("little", "big")
        for byteorder in endiannesses:
            decoded = [int.from_bytes(observation[3], byteorder) for observation in observations]
            if len(set(decoded)) < 2:
                continue
            relation = None
            constant = None
            if all(value == observation[1] for value, observation in zip(decoded, observations)):
                relation = "message_length"
            elif all(
                value == observation[1] - (observation[2] + width)
                for value, observation in zip(decoded, observations)
            ):
                relation = "remaining_bytes_after_field"
            else:
                deltas = [observation[1] - value for value, observation in zip(decoded, observations)]
                if len(set(deltas)) == 1 and 0 <= deltas[0] <= max_length_overhead:
                    relation = "message_length_minus_constant"
                    constant = deltas[0]
            if relation is None:
                continue
            candidates.append(
                {
                    "hypothesis_id": f"length-{len(candidates):04d}",
                    "alignment_start": start,
                    "alignment_end": start + width,
                    "width_bytes": width,
                    "byteorder": byteorder,
                    "relation": relation,
                    "constant": constant,
                    "sample_count": len(observations),
                    "distinct_decoded_values": len(set(decoded)),
                    "exact_match_ratio": 1.0,
                    "observations": [
                        {
                            "message_id": observation[0],
                            "original_offset_start": observation[2],
                            "original_offset_end": observation[2] + width,
                            "raw_hex": observation[3].hex(),
                            "decoded_value": value,
                            "message_length": observation[1],
                        }
                        for value, observation in zip(decoded, observations)
                    ],
                }
            )
    return candidates


def analyze_cluster(
    cluster: dict[str, Any],
    *,
    min_cluster_samples: int = 2,
    min_presence_ratio: float = 0.5,
    length_widths: tuple[int, ...] = (1, 2, 4),
    min_relation_samples: int = 3,
    max_length_overhead: int = 64,
) -> dict[str, Any]:
    if min_cluster_samples <= 0 or min_relation_samples <= 0:
        raise ValueError("sample thresholds must be positive")
    if not 0 < min_presence_ratio <= 1:
        raise ValueError("min_presence_ratio must be in (0, 1]")
    if not length_widths or any(width not in (1, 2, 4, 8) for width in length_widths):
        raise ValueError("length_widths must contain one or more of 1, 2, 4, 8")
    if max_length_overhead < 0:
        raise ValueError("max_length_overhead must be non-negative")
    columns = cluster["columns"]
    rows = cluster["rows"]
    if cluster["column_count"] != len(columns) or cluster["message_count"] != len(rows):
        raise ValueError(f"M05 cluster {cluster.get('cluster_id')} count mismatch")
    if [column["column_index"] for column in columns] != list(range(len(columns))):
        raise ValueError(f"M05 cluster {cluster.get('cluster_id')} column indexes are not contiguous")
    for row in rows:
        if len(row["cells"]) != len(columns):
            raise ValueError(f"M05 row {row.get('message_id')} cell count mismatch")
        present = [cell for cell in row["cells"] if cell is not None]
        if [cell[0] for cell in present] != list(range(row["length"])):
            raise ValueError(f"M05 row {row.get('message_id')} does not preserve original offsets")
        if any(not 0 <= cell[1] <= 255 for cell in present):
            raise ValueError(f"M05 row {row.get('message_id')} has an invalid byte value")
    column_statistics = [
        analyze_column(
            column,
            rows,
            min_cluster_samples=min_cluster_samples,
            min_presence_ratio=min_presence_ratio,
        )
        for column in columns
    ]
    fields = _segments(column_statistics)
    length_hypotheses = infer_length_relations(
        columns,
        rows,
        length_widths=length_widths,
        min_relation_samples=min_relation_samples,
        max_length_overhead=max_length_overhead,
    )
    return {
        "cluster_id": cluster["cluster_id"],
        "message_count": len(rows),
        "alignment_column_count": len(columns),
        "column_statistics": column_statistics,
        "field_candidates": fields,
        "boundary_candidates": _boundaries(fields, column_statistics),
        "length_hypotheses": length_hypotheses,
    }


def analyze_alignments(
    alignments_json: str | Path,
    output_dir: str | Path,
    *,
    min_cluster_samples: int = 2,
    min_presence_ratio: float = 0.5,
    length_widths: tuple[int, ...] = (1, 2, 4),
    min_relation_samples: int = 3,
    max_length_overhead: int = 64,
) -> dict[str, Any]:
    source = Path(alignments_json)
    if not source.is_file():
        raise FileNotFoundError(f"alignments JSON does not exist: {source}")
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    alignments = json.loads(source.read_text(encoding="utf-8"))
    ranked_boundaries = rank_framing_boundaries(_load_framing_from_alignments(source, alignments))
    parameters = {
        "min_cluster_samples": min_cluster_samples,
        "min_presence_ratio": min_presence_ratio,
        "length_widths": list(length_widths),
        "min_relation_samples": min_relation_samples,
        "max_length_overhead": max_length_overhead,
    }
    clusters = [
        analyze_cluster(cluster, **{**parameters, "length_widths": length_widths})
        for cluster in alignments.get("cluster_alignments", [])
    ]
    aligned_ids = [
        row["message_id"]
        for cluster in alignments.get("cluster_alignments", [])
        for row in cluster["rows"]
    ]
    if len(aligned_ids) != len(set(aligned_ids)):
        raise ValueError("an M05 message appears in more than one cluster alignment")
    unaligned = alignments.get("unaligned_messages", [])
    unaligned_ids = [item["message_id"] for item in unaligned]
    if len(unaligned_ids) != len(set(unaligned_ids)):
        raise ValueError("M05 unaligned messages contain duplicate ids")
    if set(aligned_ids) & set(unaligned_ids):
        raise ValueError("an M05 message is both aligned and unaligned")
    recorded_aligned = alignments.get("metrics", {}).get("aligned_message_count", 0)
    recorded_total = alignments.get("source", {}).get("message_count", 0)
    if recorded_aligned != len(aligned_ids):
        raise ValueError("M05 aligned message count does not match alignment rows")
    if recorded_total != len(aligned_ids) + len(unaligned_ids):
        raise ValueError("M05 total message count does not match aligned and unaligned messages")
    field_count = sum(len(cluster["field_candidates"]) for cluster in clusters)
    result = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "alignments_path": str(source),
            "alignments_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "stream_id": alignments.get("source", {}).get("stream_id"),
            "message_count": alignments.get("source", {}).get("message_count", 0),
            "aligned_message_count": alignments.get("metrics", {}).get("aligned_message_count", 0),
        },
        "status": "empty" if not clusters else "ok",
        "parameters": {"method": "aligned_column_statistics", **parameters},
        "cluster_formats": clusters,
        "ranked_boundary_candidates": ranked_boundaries,
        "unaligned_messages": unaligned,
        "metrics": {
            "analyzed_cluster_count": len(clusters),
            "analyzed_message_count": sum(cluster["message_count"] for cluster in clusters),
            "field_candidate_count": field_count,
            "boundary_candidate_count": sum(
                len(cluster["boundary_candidates"]) for cluster in clusters
            ),
            "length_hypothesis_count": sum(
                len(cluster["length_hypotheses"]) for cluster in clusters
            ),
            "displayed_boundary_candidate_count": len(ranked_boundaries),
        },
        "warnings": [
            "Field candidates are statistical runs, not confirmed protocol semantics.",
            "Length hypotheses require exact relations in the observed sample but may still be coincidental.",
            "Displayed boundary candidates are restricted to high-confidence framing relations; the per-cluster statistical candidates remain available for investigation.",
            "Small clusters, low-quality M05 alignments, compression, or encryption can make boundaries unreliable.",
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "format.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _parse_widths(value: str) -> tuple[int, ...]:
    try:
        widths = tuple(dict.fromkeys(int(item.strip()) for item in value.split(",") if item.strip()))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("length widths must be comma-separated integers") from exc
    if not widths or any(width not in (1, 2, 4, 8) for width in widths):
        raise argparse.ArgumentTypeError("length widths must contain one or more of 1,2,4,8")
    return widths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Infer structural field candidates from M05 alignments.")
    parser.add_argument("alignments_json", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--min-cluster-samples", type=int, default=2)
    parser.add_argument("--min-presence-ratio", type=float, default=0.5)
    parser.add_argument("--length-widths", type=_parse_widths, default=(1, 2, 4))
    parser.add_argument("--min-relation-samples", type=int, default=3)
    parser.add_argument("--max-length-overhead", type=int, default=64)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_alignments(
            args.alignments_json,
            args.output_dir,
            min_cluster_samples=args.min_cluster_samples,
            min_presence_ratio=args.min_presence_ratio,
            length_widths=args.length_widths,
            min_relation_samples=args.min_relation_samples,
            max_length_overhead=args.max_length_overhead,
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"m06: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "format.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

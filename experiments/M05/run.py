#!/usr/bin/env python3
"""M5 byte-level reference alignment for M4 message clusters."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "0.1"
DIAGONAL = 0
UP = 1
LEFT = 2


def needleman_wunsch(
    reference: bytes,
    target: bytes,
    *,
    match_score: int = 2,
    mismatch_score: int = -1,
    gap_score: int = -2,
    max_pair_cells: int = 2_000_000,
) -> dict[str, Any]:
    """Globally align two byte strings and preserve offsets into both inputs."""
    if match_score <= mismatch_score:
        raise ValueError("match_score must be greater than mismatch_score")
    if gap_score >= 0:
        raise ValueError("gap_score must be negative")
    rows = len(reference) + 1
    columns = len(target) + 1
    cell_count = rows * columns
    if max_pair_cells <= 0 or cell_count > max_pair_cells:
        raise ValueError(
            f"alignment requires {cell_count} cells, exceeding limit {max_pair_cells}"
        )

    directions = [bytearray(columns) for _ in range(rows)]
    for column in range(1, columns):
        directions[0][column] = LEFT
    previous = [column * gap_score for column in range(columns)]
    for row in range(1, rows):
        current = [0] * columns
        current[0] = row * gap_score
        directions[row][0] = UP
        reference_byte = reference[row - 1]
        for column in range(1, columns):
            diagonal = previous[column - 1] + (
                match_score if reference_byte == target[column - 1] else mismatch_score
            )
            up = previous[column] + gap_score
            left = current[column - 1] + gap_score
            best = diagonal
            direction = DIAGONAL
            if up > best:
                best = up
                direction = UP
            if left > best:
                best = left
                direction = LEFT
            current[column] = best
            directions[row][column] = direction
        previous = current

    reference_offset = len(reference)
    target_offset = len(target)
    reversed_pairs: list[tuple[int | None, int | None]] = []
    while reference_offset or target_offset:
        direction = directions[reference_offset][target_offset]
        if direction == DIAGONAL:
            reference_offset -= 1
            target_offset -= 1
            reversed_pairs.append((reference_offset, target_offset))
        elif direction == UP:
            reference_offset -= 1
            reversed_pairs.append((reference_offset, None))
        else:
            target_offset -= 1
            reversed_pairs.append((None, target_offset))
    pairs = list(reversed(reversed_pairs))

    matches = sum(
        reference[left] == target[right]
        for left, right in pairs
        if left is not None and right is not None
    )
    paired = sum(left is not None and right is not None for left, right in pairs)
    gaps_in_target = sum(right is None for _, right in pairs)
    gaps_in_reference = sum(left is None for left, _ in pairs)
    return {
        "score": previous[-1],
        "pairs": pairs,
        "matches": matches,
        "mismatches": paired - matches,
        "gaps_in_target": gaps_in_target,
        "gaps_in_reference": gaps_in_reference,
        "identity_on_paired_bytes": matches / paired if paired else None,
    }


def _alignment_maps(
    pairs: list[tuple[int | None, int | None]], reference_length: int
) -> tuple[dict[int, int | None], dict[int, list[int]]]:
    reference_map: dict[int, int | None] = {}
    insertions = {anchor: [] for anchor in range(reference_length + 1)}
    anchor = 0
    for reference_offset, target_offset in pairs:
        if reference_offset is None:
            if target_offset is None:
                raise ValueError("alignment cannot contain a double gap")
            insertions[anchor].append(target_offset)
        else:
            reference_map[reference_offset] = target_offset
            anchor = reference_offset + 1
    if set(reference_map) != set(range(reference_length)):
        raise ValueError("alignment does not cover every reference offset")
    return reference_map, insertions


def align_cluster(
    cluster_id: int,
    message_ids: list[str],
    representative_message_id: str,
    messages: dict[str, bytes],
    **parameters: Any,
) -> dict[str, Any]:
    if representative_message_id not in message_ids:
        raise ValueError(f"cluster {cluster_id} representative is not a member")
    if len(set(message_ids)) != len(message_ids):
        raise ValueError(f"cluster {cluster_id} contains duplicate message ids")
    missing = [message_id for message_id in message_ids if message_id not in messages]
    if missing:
        raise ValueError(f"cluster {cluster_id} messages missing from framing: {missing[:5]}")

    reference = messages[representative_message_id]
    pairwise: dict[str, dict[str, Any]] = {}
    maps: dict[str, tuple[dict[int, int | None], dict[int, list[int]]]] = {}
    for message_id in message_ids:
        result = needleman_wunsch(reference, messages[message_id], **parameters)
        pairwise[message_id] = result
        maps[message_id] = _alignment_maps(result["pairs"], len(reference))

    insertion_widths = {
        anchor: max(len(maps[message_id][1][anchor]) for message_id in message_ids)
        for anchor in range(len(reference) + 1)
    }
    columns: list[dict[str, Any]] = []
    for anchor in range(len(reference) + 1):
        for ordinal in range(insertion_widths[anchor]):
            columns.append(
                {
                    "column_index": len(columns),
                    "kind": "insertion",
                    "reference_offset": None,
                    "insertion_anchor": anchor,
                    "insertion_ordinal": ordinal,
                }
            )
        if anchor < len(reference):
            columns.append(
                {
                    "column_index": len(columns),
                    "kind": "reference",
                    "reference_offset": anchor,
                    "insertion_anchor": anchor,
                    "insertion_ordinal": None,
                }
            )

    rows: list[dict[str, Any]] = []
    for message_id in message_ids:
        data = messages[message_id]
        reference_map, insertions = maps[message_id]
        cells: list[list[int] | None] = []
        for column in columns:
            if column["kind"] == "reference":
                offset = reference_map[column["reference_offset"]]
            else:
                values = insertions[column["insertion_anchor"]]
                ordinal = column["insertion_ordinal"]
                offset = values[ordinal] if ordinal < len(values) else None
            cells.append(None if offset is None else [offset, data[offset]])
        result = pairwise[message_id]
        rows.append(
            {
                "message_id": message_id,
                "length": len(data),
                "is_representative": message_id == representative_message_id,
                "score": result["score"],
                "matches": result["matches"],
                "mismatches": result["mismatches"],
                "gaps_in_message": result["gaps_in_target"],
                "gaps_in_reference": result["gaps_in_reference"],
                "identity_on_paired_bytes": result["identity_on_paired_bytes"],
                "cells": cells,
            }
        )
    return {
        "cluster_id": cluster_id,
        "representative_message_id": representative_message_id,
        "message_count": len(message_ids),
        "reference_length": len(reference),
        "column_count": len(columns),
        "columns": columns,
        "rows": rows,
    }


def _resolve_framing_path(
    clusters_path: Path, recorded_path: str, override: str | Path | None
) -> Path:
    if override is not None:
        candidate = Path(override)
        if not candidate.is_file():
            raise FileNotFoundError(f"framing JSON does not exist: {candidate}")
        return candidate
    recorded = Path(recorded_path)
    candidates = [recorded]
    if not recorded.is_absolute():
        candidates.append(clusters_path.parent / recorded)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "recorded framing JSON cannot be found; pass --framing-json explicitly"
    )


def _load_messages(framing_path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    framing = json.loads(framing_path.read_text(encoding="utf-8"))
    base = framing_path.parent.resolve()
    messages: dict[str, bytes] = {}
    for item in framing.get("messages", []):
        message_id = str(item.get("id"))
        if message_id in messages:
            raise ValueError(f"duplicate message id in framing: {message_id}")
        reference = item.get("artifact_ref")
        if not reference:
            raise ValueError(f"message {message_id} has no artifact_ref")
        artifact = (base / reference).resolve()
        try:
            artifact.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"artifact_ref escapes framing directory: {reference}") from exc
        data = artifact.read_bytes()
        if len(data) != item.get("length"):
            raise ValueError(f"message length mismatch for {message_id}")
        messages[message_id] = data
    return framing, messages


def analyze_clusters(
    clusters_json: str | Path,
    output_dir: str | Path,
    *,
    framing_json: str | Path | None = None,
    match_score: int = 2,
    mismatch_score: int = -1,
    gap_score: int = -2,
    max_pair_cells: int = 2_000_000,
) -> dict[str, Any]:
    source = Path(clusters_json)
    if not source.is_file():
        raise FileNotFoundError(f"clusters JSON does not exist: {source}")
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    clusters = json.loads(source.read_text(encoding="utf-8"))
    recorded_framing = clusters.get("source", {}).get("framing_path")
    if not isinstance(recorded_framing, str):
        raise ValueError("clusters source has no framing_path")
    framing_path = _resolve_framing_path(source, recorded_framing, framing_json)
    framing_bytes = framing_path.read_bytes()
    expected_digest = clusters.get("source", {}).get("framing_sha256")
    if hashlib.sha256(framing_bytes).hexdigest() != expected_digest:
        raise ValueError("framing JSON hash does not match M04 source record")
    framing, messages = _load_messages(framing_path)
    if len(messages) != clusters.get("source", {}).get("message_count"):
        raise ValueError("framing message count does not match M04 source record")

    parameters = {
        "match_score": match_score,
        "mismatch_score": mismatch_score,
        "gap_score": gap_score,
        "max_pair_cells": max_pair_cells,
    }
    aligned_clusters = [
        align_cluster(
            int(cluster["cluster_id"]),
            [str(value) for value in cluster["message_ids"]],
            str(cluster["representative_message_id"]),
            messages,
            **parameters,
        )
        for cluster in clusters.get("clusters", [])
    ]
    aligned_sequence = [
        row["message_id"] for cluster in aligned_clusters for row in cluster["rows"]
    ]
    aligned_ids = set(aligned_sequence)
    if len(aligned_sequence) != len(aligned_ids):
        raise ValueError("a message appears in more than one M04 cluster")
    assignment_ids = [str(item["message_id"]) for item in clusters.get("assignments", [])]
    if len(assignment_ids) != len(set(assignment_ids)):
        raise ValueError("M04 assignments contain duplicate message ids")
    if set(assignment_ids) != set(messages):
        raise ValueError("M04 assignments do not match framed message ids")
    unaligned = [message_id for message_id in assignment_ids if message_id not in aligned_ids]
    inconsistent = [
        str(item["message_id"])
        for item in clusters.get("assignments", [])
        if bool(item.get("is_noise")) != (str(item["message_id"]) not in aligned_ids)
    ]
    if inconsistent:
        raise ValueError(f"M04 noise assignments disagree with cluster membership: {inconsistent[:5]}")
    identities = [
        row["identity_on_paired_bytes"]
        for cluster in aligned_clusters
        for row in cluster["rows"]
        if row["identity_on_paired_bytes"] is not None
    ]
    result = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "clusters_path": str(source),
            "clusters_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "framing_path": str(framing_path),
            "framing_sha256": hashlib.sha256(framing_bytes).hexdigest(),
            "stream_id": framing.get("source", {}).get("id"),
            "message_count": len(messages),
        },
        "status": "empty" if not messages else "ok",
        "parameters": {"algorithm": "needleman_wunsch_reference", **parameters},
        "cluster_alignments": aligned_clusters,
        "unaligned_messages": [
            {"message_id": message_id, "reason": "m04_noise"} for message_id in unaligned
        ],
        "metrics": {
            "aligned_cluster_count": len(aligned_clusters),
            "aligned_message_count": len(aligned_ids),
            "unaligned_message_count": len(unaligned),
            "total_alignment_columns": sum(
                cluster["column_count"] for cluster in aligned_clusters
            ),
            "mean_identity_on_paired_bytes": (
                sum(identities) / len(identities) if identities else None
            ),
        },
        "warnings": [
            "Alignment columns are relative to each M04 representative, not a globally optimal multiple alignment.",
            "Stable columns and high identity do not by themselves establish field semantics.",
        ],
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "alignments.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Align messages within M04 clusters.")
    parser.add_argument("clusters_json", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--framing-json", type=Path)
    parser.add_argument("--match-score", type=int, default=2)
    parser.add_argument("--mismatch-score", type=int, default=-1)
    parser.add_argument("--gap-score", type=int, default=-2)
    parser.add_argument("--max-pair-cells", type=int, default=2_000_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_clusters(
            args.clusters_json,
            args.output_dir,
            framing_json=args.framing_json,
            match_score=args.match_score,
            mismatch_score=args.mismatch_score,
            gap_score=args.gap_score,
            max_pair_cells=args.max_pair_cells,
        )
    except (FileNotFoundError, FileExistsError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"m05: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "alignments.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

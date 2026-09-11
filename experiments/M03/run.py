#!/usr/bin/env python3
"""M3 explainable framing baselines for continuous byte streams."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "0.1"


def _validate_range(start: int, end: int, length: int) -> None:
    if not 0 <= start <= end <= length:
        raise ValueError(f"invalid range [{start},{end}) for stream length {length}")


def _message(stream_id: str, index: int, start: int, end: int) -> dict[str, Any]:
    return {
        "id": f"{stream_id}-message-{index:06d}",
        "stream_id": stream_id,
        "start": start,
        "end": end,
        "length": end - start,
        "complete": True,
        "framing_evidence": [],
    }


def _unparsed_ranges(length: int, messages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    cursor = 0
    for item in sorted(messages, key=lambda value: value["start"]):
        start, end = item["start"], item["end"]
        _validate_range(start, end, length)
        if start < cursor:
            raise ValueError("accepted message ranges overlap")
        if cursor < start:
            ranges.append(
                {
                    "start": cursor,
                    "end": start,
                    "length": start - cursor,
                    "reason": "not_accepted_by_rule",
                }
            )
        cursor = end
    if cursor < length:
        ranges.append(
            {
                "start": cursor,
                "end": length,
                "length": length - cursor,
                "reason": "not_accepted_by_rule",
            }
        )
    return ranges


def frame_length_prefixed(
    data: bytes,
    *,
    stream_id: str,
    magic: bytes = b"",
    length_offset: int,
    length_width: int,
    byteorder: str,
    length_mode: str,
    header_size: int,
    trailer_size: int = 0,
    start_offset: int = 0,
    max_frame_length: int = 1024 * 1024,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if length_offset < 0 or length_width <= 0 or length_width > 8:
        raise ValueError("length_offset must be non-negative and length_width must be 1..8")
    if byteorder not in ("big", "little"):
        raise ValueError("byteorder must be big or little")
    if length_mode not in ("payload", "frame"):
        raise ValueError("length_mode must be payload or frame")
    if header_size < length_offset + length_width:
        raise ValueError("header_size does not contain the length field")
    if trailer_size < 0 or max_frame_length <= 0:
        raise ValueError("trailer_size must be non-negative and max_frame_length positive")
    _validate_range(start_offset, start_offset, len(data))

    messages: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    cursor = start_offset
    minimum = header_size + trailer_size
    while cursor < len(data):
        candidate = data.find(magic, cursor) if magic else cursor
        if candidate < 0:
            break
        next_search = candidate + (1 if magic else 0)
        field_start = candidate + length_offset
        field_end = field_start + length_width
        if field_end > len(data):
            diagnostics.append(
                {"offset": candidate, "rule_id": "M03-LEN-TRUNCATED-HEADER", "accepted": False}
            )
            if not magic:
                break
            cursor = next_search
            continue
        raw_length = int.from_bytes(data[field_start:field_end], byteorder=byteorder)
        frame_length = (
            header_size + raw_length + trailer_size
            if length_mode == "payload"
            else raw_length
        )
        if frame_length < minimum or frame_length > max_frame_length:
            diagnostics.append(
                {
                    "offset": candidate,
                    "rule_id": "M03-LEN-OUT-OF-RANGE",
                    "accepted": False,
                    "decoded_length": raw_length,
                    "computed_frame_length": frame_length,
                }
            )
            if not magic:
                break
            cursor = next_search
            continue
        end = candidate + frame_length
        if end > len(data):
            diagnostics.append(
                {
                    "offset": candidate,
                    "rule_id": "M03-LEN-TRUNCATED-FRAME",
                    "accepted": False,
                    "decoded_length": raw_length,
                    "computed_frame_length": frame_length,
                    "available_length": len(data) - candidate,
                }
            )
            if not magic:
                break
            cursor = next_search
            continue
        item = _message(stream_id, len(messages), candidate, end)
        item["framing_evidence"] = [
            {
                "rule_id": "M03-LENGTH-PREFIX",
                "magic_hex": magic.hex() if magic else None,
                "length_field_range": [field_start, field_end],
                "decoded_length": raw_length,
                "length_mode": length_mode,
            }
        ]
        messages.append(item)
        diagnostics.append(
            {
                "offset": candidate,
                "rule_id": "M03-LENGTH-PREFIX",
                "accepted": True,
                "computed_frame_length": frame_length,
            }
        )
        cursor = end
    parameters = {
        "magic_hex": magic.hex(),
        "length_offset": length_offset,
        "length_width": length_width,
        "byteorder": byteorder,
        "length_mode": length_mode,
        "header_size": header_size,
        "trailer_size": trailer_size,
        "start_offset": start_offset,
        "max_frame_length": max_frame_length,
    }
    return messages, diagnostics, parameters


def frame_delimited(
    data: bytes,
    *,
    stream_id: str,
    delimiter: bytes,
    include_delimiter: bool = True,
    start_offset: int = 0,
    allow_empty: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if not delimiter:
        raise ValueError("delimiter must not be empty")
    _validate_range(start_offset, start_offset, len(data))
    messages: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    cursor = start_offset
    while True:
        found = data.find(delimiter, cursor)
        if found < 0:
            break
        payload_end = found
        accepted_end = found + len(delimiter) if include_delimiter else found
        if allow_empty or payload_end > cursor:
            item = _message(stream_id, len(messages), cursor, accepted_end)
            item["framing_evidence"] = [
                {
                    "rule_id": "M03-DELIMITER",
                    "delimiter_hex": delimiter.hex(),
                    "delimiter_range": [found, found + len(delimiter)],
                    "delimiter_included": include_delimiter,
                }
            ]
            messages.append(item)
            diagnostics.append(
                {"offset": cursor, "rule_id": "M03-DELIMITER", "accepted": True}
            )
        else:
            diagnostics.append(
                {"offset": cursor, "rule_id": "M03-DELIMITER-EMPTY", "accepted": False}
            )
        cursor = found + len(delimiter)
    parameters = {
        "delimiter_hex": delimiter.hex(),
        "include_delimiter": include_delimiter,
        "start_offset": start_offset,
        "allow_empty": allow_empty,
    }
    return messages, diagnostics, parameters


def frame_fixed(
    data: bytes,
    *,
    stream_id: str,
    frame_size: int,
    start_offset: int = 0,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if frame_size <= 0:
        raise ValueError("frame_size must be positive")
    _validate_range(start_offset, start_offset, len(data))
    messages: list[dict[str, Any]] = []
    cursor = start_offset
    while cursor + frame_size <= len(data):
        item = _message(stream_id, len(messages), cursor, cursor + frame_size)
        item["framing_evidence"] = [
            {"rule_id": "M03-FIXED-LENGTH", "frame_size": frame_size}
        ]
        messages.append(item)
        cursor += frame_size
    diagnostics = [
        {"offset": item["start"], "rule_id": "M03-FIXED-LENGTH", "accepted": True}
        for item in messages
    ]
    if cursor < len(data):
        diagnostics.append(
            {
                "offset": cursor,
                "rule_id": "M03-FIXED-TRAILING-PARTIAL",
                "accepted": False,
                "available_length": len(data) - cursor,
            }
        )
    return messages, diagnostics, {"frame_size": frame_size, "start_offset": start_offset}


def infer_length_prefixed(
    data: bytes,
    *,
    stream_id: str,
    max_header_size: int = 12,
    max_frame_length: int = 1024 * 1024,
    min_frames: int = 3,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Conservatively discover a repeated length-prefixed framing hypothesis.

    Only hypotheses that tile the entire stream from offset zero are accepted.
    Coincidental byte values are therefore left unframed rather than presented
    as protocol truth.
    """
    if max_header_size < 2 or max_frame_length <= 0 or min_frames < 2:
        raise ValueError("invalid automatic framing limits")
    candidates: list[tuple[tuple[int, int, int, int, int], list[dict[str, Any]], dict[str, Any]]] = []
    for length_offset in range(min(8, max_header_size - 1) + 1):
        for length_width in (1, 2, 4):
            field_end = length_offset + length_width
            if field_end > max_header_size or field_end > len(data):
                continue
            for header_size in range(field_end, min(max_header_size, len(data)) + 1):
                for byteorder in ("big", "little"):
                    for length_mode in ("payload", "frame"):
                        messages, _diagnostics, parameters = frame_length_prefixed(
                            data, stream_id=stream_id, magic=b"",
                            length_offset=length_offset, length_width=length_width,
                            byteorder=byteorder, length_mode=length_mode,
                            header_size=header_size, max_frame_length=max_frame_length,
                        )
                        if len(messages) < min_frames or _unparsed_ranges(len(data), messages):
                            continue
                        score = (len(messages), len({item["length"] for item in messages}),
                                 length_width, -header_size, -length_offset)
                        candidates.append((score, messages, parameters))
    if not candidates:
        return [], [{"rule_id": "M03-INFERENCE-INSUFFICIENT-EVIDENCE", "accepted": False}], {
            "method": "repeated_length_prefix_search", "candidate_count": 0,
            "min_frames": min_frames, "max_header_size": max_header_size,
        }
    candidates.sort(key=lambda item: item[0], reverse=True)
    _score, messages, parameters = candidates[0]
    selected = {key: parameters[key] for key in (
        "length_offset", "length_width", "byteorder", "length_mode", "header_size"
    )}
    for message in messages:
        message["framing_evidence"] = [{
            "rule_id": "M03-INFERRED-LENGTH-PREFIX", "selection": selected,
            "basis": "repeated self-consistent length-prefixed frames cover the complete input",
        }]
    return messages, [{
        "rule_id": "M03-INFERRED-LENGTH-PREFIX", "accepted": True,
        "candidate_count": len(candidates), "selected": selected,
    }], {
        "method": "repeated_length_prefix_search", "candidate_count": len(candidates),
        "min_frames": min_frames, "max_header_size": max_header_size,
        "max_frame_length": max_frame_length, "selected": selected,
    }


def evaluate_framing(
    predicted: Iterable[tuple[int, int]],
    expected: Iterable[tuple[int, int]],
    *,
    stream_length: int,
    exclude_outer_boundaries: bool = True,
) -> dict[str, Any]:
    predicted_set = set(predicted)
    expected_set = set(expected)
    for start, end in predicted_set | expected_set:
        _validate_range(start, end, stream_length)
    excluded = {0, stream_length} if exclude_outer_boundaries else set()
    predicted_boundaries = {value for pair in predicted_set for value in pair} - excluded
    expected_boundaries = {value for pair in expected_set for value in pair} - excluded
    matched = len(predicted_boundaries & expected_boundaries)
    precision = matched / len(predicted_boundaries) if predicted_boundaries else (
        1.0 if not expected_boundaries else 0.0
    )
    recall = matched / len(expected_boundaries) if expected_boundaries else (
        1.0 if not predicted_boundaries else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    exact = len(predicted_set & expected_set)
    return {
        "exclude_outer_boundaries": exclude_outer_boundaries,
        "boundary_true_positive": matched,
        "boundary_precision": precision,
        "boundary_recall": recall,
        "boundary_f1": f1,
        "exact_message_matches": exact,
        "expected_message_count": len(expected_set),
        "complete_message_match_rate": exact / len(expected_set) if expected_set else 1.0,
    }


def analyze_file(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    rule: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    source = Path(input_path)
    if not source.exists():
        raise FileNotFoundError(f"input does not exist: {source}")
    if not source.is_file():
        raise ValueError(f"input is not a regular file: {source}")
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    stream_id = f"{source.stem or 'stream'}-{digest[:12]}"
    if rule == "length":
        messages, diagnostics, normalized = frame_length_prefixed(
            data, stream_id=stream_id, **parameters
        )
    elif rule == "delimiter":
        messages, diagnostics, normalized = frame_delimited(
            data, stream_id=stream_id, **parameters
        )
    elif rule == "fixed":
        messages, diagnostics, normalized = frame_fixed(
            data, stream_id=stream_id, **parameters
        )
    elif rule == "infer":
        messages, diagnostics, normalized = infer_length_prefixed(
            data, stream_id=stream_id, **parameters
        )
    else:
        raise ValueError(f"unknown rule: {rule}")
    uncovered = _unparsed_ranges(len(data), messages)
    status = "complete" if messages and not uncovered else "partial" if messages else "unframed"
    result = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "id": stream_id,
            "path": str(source),
            "sha256": digest,
            "length": len(data),
        },
        "status": "empty" if not data else status,
        "rule": rule,
        "parameters": normalized,
        "messages": messages,
        "unparsed_ranges": uncovered,
        "diagnostics": diagnostics,
        "warnings": [
            "Framing boundaries are hypotheses, not protocol truth.",
            "Automatic inference accepts only self-consistent repeated length-prefix evidence; other formats remain unframed."
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        if messages:
            message_dir = staging / "messages"
            message_dir.mkdir()
            for item in messages:
                artifact = message_dir / f"{item['id']}.bin"
                artifact.write_bytes(data[item["start"] : item["end"]])
                item["artifact_ref"] = artifact.relative_to(staging).as_posix()
        (staging / "framing.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Frame a continuous byte stream using an explicit or conservative inferred rule.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rule", choices=("length", "delimiter", "fixed", "infer"), required=True)
    parser.add_argument("--magic-hex", default="")
    parser.add_argument("--length-offset", type=int)
    parser.add_argument("--length-width", type=int)
    parser.add_argument("--byteorder", choices=("big", "little"), default="big")
    parser.add_argument("--length-mode", choices=("payload", "frame"), default="payload")
    parser.add_argument("--header-size", type=int)
    parser.add_argument("--trailer-size", type=int, default=0)
    parser.add_argument("--max-frame-length", type=int, default=1024 * 1024)
    parser.add_argument("--delimiter-hex")
    parser.add_argument("--exclude-delimiter", action="store_true")
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--frame-size", type=int)
    parser.add_argument("--start-offset", type=int, default=0)
    parser.add_argument("--max-header-size", type=int, default=12)
    parser.add_argument("--min-frames", type=int, default=3)
    return parser


def _parameters_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.rule == "infer":
        return {"max_header_size": args.max_header_size, "max_frame_length": args.max_frame_length,
                "min_frames": args.min_frames}
    if args.rule == "length":
        if args.length_offset is None or args.length_width is None or args.header_size is None:
            raise ValueError("length rule requires --length-offset, --length-width, and --header-size")
        return {
            "magic": bytes.fromhex(args.magic_hex),
            "length_offset": args.length_offset,
            "length_width": args.length_width,
            "byteorder": args.byteorder,
            "length_mode": args.length_mode,
            "header_size": args.header_size,
            "trailer_size": args.trailer_size,
            "start_offset": args.start_offset,
            "max_frame_length": args.max_frame_length,
        }
    if args.rule == "delimiter":
        if args.delimiter_hex is None:
            raise ValueError("delimiter rule requires --delimiter-hex")
        return {
            "delimiter": bytes.fromhex(args.delimiter_hex),
            "include_delimiter": not args.exclude_delimiter,
            "start_offset": args.start_offset,
            "allow_empty": args.allow_empty,
        }
    if args.frame_size is None:
        raise ValueError("fixed rule requires --frame-size")
    return {"frame_size": args.frame_size, "start_offset": args.start_offset}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        parameters = _parameters_from_args(args)
        analyze_file(args.input, args.output_dir, rule=args.rule, parameters=parameters)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"m03: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "framing.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

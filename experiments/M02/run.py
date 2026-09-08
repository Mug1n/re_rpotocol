#!/usr/bin/env python3
"""M2 deterministic byte-level feature extraction CLI."""

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


def _entropy(counts: list[int], length: int) -> float | None:
    if length == 0:
        return None
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def _ratios(data: bytes) -> tuple[float | None, float | None, float | None]:
    if not data:
        return None, None, None
    length = len(data)
    printable = sum(0x20 <= byte <= 0x7E for byte in data) / length
    whitespace = sum(byte in (0x09, 0x0A, 0x0D) for byte in data) / length
    zero = data.count(0) / length
    return printable, whitespace, zero


def _summary(data: bytes) -> dict[str, Any]:
    counts_counter = Counter(data)
    counts = [counts_counter.get(byte, 0) for byte in range(256)]
    length = len(data)
    frequencies = [count / length if length else 0.0 for count in counts]
    printable, whitespace, zero = _ratios(data)
    return {
        "length": length,
        "byte_counts": counts,
        "byte_frequencies": frequencies,
        "entropy_bits_per_byte": _entropy(counts, length),
        "printable_ascii_ratio": printable,
        "ascii_whitespace_ratio": whitespace,
        "zero_ratio": zero,
    }


def _top_bytes(data: bytes, limit: int) -> list[dict[str, Any]]:
    if not data or limit == 0:
        return []
    counts = Counter(data)
    return [
        {
            "byte": byte,
            "hex": f"{byte:02x}",
            "count": count,
            "frequency": count / len(data),
        }
        for byte, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[
            :limit
        ]
    ]


def _repeated_patterns(
    data: bytes,
    sizes: tuple[int, ...],
    pattern_limit: int,
    offset_limit: int,
) -> list[dict[str, Any]]:
    candidates: list[tuple[int, bytes, list[int]]] = []
    for size in sizes:
        if size <= 0 or size > len(data):
            continue
        offsets_by_value: dict[bytes, list[int]] = {}
        for offset in range(0, len(data) - size + 1):
            value = data[offset : offset + size]
            offsets_by_value.setdefault(value, []).append(offset)
        for value, offsets in offsets_by_value.items():
            if len(offsets) >= 2:
                candidates.append((size, value, offsets))
    candidates.sort(key=lambda item: (-len(item[2]), -item[0], item[1]))
    return [
        {
            "size": size,
            "hex": value.hex(),
            "count": len(offsets),
            "offsets": offsets[:offset_limit],
            "offsets_truncated": len(offsets) > offset_limit,
        }
        for size, value, offsets in candidates[:pattern_limit]
    ]


def analyze_bytes(
    data: bytes,
    *,
    source_id: str,
    source_path: str,
    source_sha256: str,
    window_size: int = 256,
    window_step: int | None = None,
    top_n: int = 8,
    ngram_sizes: tuple[int, ...] = (2, 3, 4),
    pattern_limit: int = 20,
    pattern_offset_limit: int = 32,
) -> dict[str, Any]:
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    step = window_size if window_step is None else window_step
    if step <= 0:
        raise ValueError("window_step must be positive")
    if top_n < 0 or pattern_limit < 0 or pattern_offset_limit < 0:
        raise ValueError("limits must be non-negative")
    if any(size <= 0 for size in ngram_sizes):
        raise ValueError("ngram sizes must be positive")

    windows: list[dict[str, Any]] = []
    for start in range(0, len(data), step):
        end = min(start + window_size, len(data))
        chunk = data[start:end]
        if not chunk:
            break
        windows.append({"start": start, "end": end, **_summary(chunk)})
        if end == len(data):
            break

    global_features = _summary(data)
    global_features.update(
        {
            "top_bytes": _top_bytes(data, top_n),
            "prefix_preview_hex": data[: min(16, len(data))].hex(),
            "repeated_patterns": _repeated_patterns(
                data, tuple(sorted(set(ngram_sizes))), pattern_limit, pattern_offset_limit
            ),
        }
    )
    warnings = [
        "Entropy alone cannot distinguish encryption, compression, and random data."
    ]
    if not data:
        warnings.append("Ratios and entropy are undefined for empty input.")
    return {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "id": source_id,
            "path": source_path,
            "sha256": source_sha256,
            "range": {"start": 0, "end": len(data)},
        },
        "status": "empty" if not data else "ok",
        "parameters": {
            "entropy_log_base": 2,
            "printable_ascii_range": [32, 126],
            "ascii_whitespace_bytes": [9, 10, 13],
            "window_size": window_size,
            "window_step": step,
            "tail_window": "include_short_tail",
            "top_n": top_n,
            "ngram_sizes": sorted(set(ngram_sizes)),
            "pattern_limit": pattern_limit,
            "pattern_offset_limit": pattern_offset_limit,
            "ngram_counting": "overlapping",
        },
        "global": global_features,
        "windows": windows,
        "warnings": warnings,
    }


def analyze_file(
    input_path: str | Path,
    output_dir: str | Path,
    **parameters: Any,
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
    source_id = f"{source.stem or 'input'}-{digest[:12]}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        result = analyze_bytes(
            data,
            source_id=source_id,
            source_path=str(source),
            source_sha256=digest,
            **parameters,
        )
        (staging / "features.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute deterministic global and windowed features for bytes."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--window-size", type=int, default=256)
    parser.add_argument("--window-step", type=int)
    parser.add_argument("--top-n", type=int, default=8)
    parser.add_argument("--ngram-size", type=int, action="append", dest="ngram_sizes")
    parser.add_argument("--pattern-limit", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_file(
            args.input,
            args.output_dir,
            window_size=args.window_size,
            window_step=args.window_step,
            top_n=args.top_n,
            ngram_sizes=tuple(args.ngram_sizes or (2, 3, 4)),
            pattern_limit=args.pattern_limit,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"m02: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "features.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

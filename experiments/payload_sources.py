#!/usr/bin/env python3
"""Extract provenance-preserving HTTP body sources from every M01 TCP direction."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import load_json_artifact_with_sha256, validate_m01_references


SCHEMA_VERSION = "0.1"
M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
OUTPUT_SCHEMA = ROOT / "research" / "M08-recovery" / "payload-sources.schema.json"
DEFAULT_MAX_STREAM_BYTES = 64 * 1024 * 1024
REQUEST_METHODS = {b"GET", b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE"}
REQUEST_LINE = re.compile(rb"([A-Z]+) ([^\x00-\x20\x7f]+) HTTP/[0-9]+\.[0-9]+")
RESPONSE_LINE = re.compile(rb"HTTP/[0-9]+\.[0-9]+ [0-9]{3}(?: [^\r\n]*)?")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _resolve(artifact_path: Path, reference: str) -> Path:
    value = Path(reference)
    if value.is_absolute():
        return value
    nearby = artifact_path.parent / value
    return nearby if nearby.is_file() else Path.cwd() / value


def _headers(block: bytes) -> tuple[str, str, dict[str, str]] | None:
    lines = block.split(b"\r\n")
    if not lines:
        return None
    start_raw = lines[0]
    response_match = RESPONSE_LINE.fullmatch(start_raw)
    request_match = REQUEST_LINE.fullmatch(start_raw)
    if response_match:
        message_type = "response"
    elif request_match and request_match.group(1) in REQUEST_METHODS:
        message_type = "request"
    else:
        return None
    try:
        start_line = start_raw.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            return None
        name, value = line.split(b":", 1)
        if HEADER_NAME.fullmatch(name) is None:
            return None
        try:
            normalized = name.decode("ascii").strip().lower()
            decoded = value.decode("iso-8859-1").strip()
        except UnicodeDecodeError:
            return None
        if not normalized or normalized in parsed:
            return None
        parsed[normalized] = decoded
    return message_type, start_line, parsed


def _chunked(data: bytes, start: int) -> tuple[bytes, list[dict[str, int]], int, bool, str | None]:
    cursor = start
    output = bytearray()
    ranges: list[dict[str, int]] = []
    while True:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0:
            return bytes(output), ranges, len(data), False, "TRUNCATED_CHUNK_SIZE"
        raw_size = data[cursor:line_end].split(b";", 1)[0].strip()
        try:
            size = int(raw_size, 16)
        except ValueError:
            return bytes(output), ranges, line_end + 2, False, "INVALID_CHUNK_SIZE"
        cursor = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", cursor)
            if data[cursor:cursor + 2] == b"\r\n":
                return bytes(output), ranges, cursor + 2, True, None
            if trailer_end < 0:
                return bytes(output), ranges, len(data), False, "TRUNCATED_CHUNK_TRAILER"
            return bytes(output), ranges, trailer_end + 4, True, None
        end = cursor + size
        if end > len(data):
            if cursor < len(data):
                output.extend(data[cursor:])
                ranges.append({"start": cursor, "end": len(data)})
            return bytes(output), ranges, len(data), False, "TRUNCATED_CHUNK_DATA"
        output.extend(data[cursor:end])
        ranges.append({"start": cursor, "end": end})
        if data[end:end + 2] != b"\r\n":
            return bytes(output), ranges, min(end + 2, len(data)), False, "INVALID_CHUNK_TERMINATOR"
        cursor = end + 2


def _http_bodies(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bodies: list[dict[str, Any]] = []
    unparsed: list[dict[str, Any]] = []
    cursor = 0
    message_index = 0
    while cursor < len(data):
        header_end = data.find(b"\r\n\r\n", cursor)
        if header_end < 0:
            unparsed.append({"start": cursor, "end": len(data), "reason": "HTTP_HEADER_TERMINATOR_NOT_FOUND"})
            break
        parsed = _headers(data[cursor:header_end])
        if parsed is None:
            unparsed.append({"start": cursor, "end": len(data), "reason": "HTTP_START_LINE_OR_HEADERS_INVALID"})
            break
        message_type, start_line, headers = parsed
        body_start = header_end + 4
        framing = "no_body"
        body = b""
        ranges: list[dict[str, int]] = []
        complete = True
        reason = None
        next_cursor = body_start
        transfer_tokens = {item.strip().lower() for item in headers.get("transfer-encoding", "").split(",") if item.strip()}
        if "chunked" in transfer_tokens:
            framing = "chunked"
            body, ranges, next_cursor, complete, reason = _chunked(data, body_start)
        elif "content-length" in headers:
            framing = "content_length"
            try:
                declared = int(headers["content-length"])
            except ValueError:
                declared = -1
            if declared < 0:
                unparsed.append({"start": body_start, "end": len(data), "reason": "INVALID_CONTENT_LENGTH"})
                break
            available_end = min(body_start + declared, len(data))
            body = data[body_start:available_end]
            if body:
                ranges = [{"start": body_start, "end": available_end}]
            complete = len(body) == declared
            reason = None if complete else "TRUNCATED_CONTENT_LENGTH_BODY"
            next_cursor = available_end
        elif message_type == "response" and not _response_has_no_body(start_line):
            unparsed.append({"start": body_start, "end": len(data), "reason": "HTTP_BODY_BOUNDARY_UNAVAILABLE"})
            break
        if body or framing in {"content_length", "chunked"}:
            bodies.append({
                "message_index": message_index,
                "message_type": message_type,
                "start_line": start_line,
                "headers": headers,
                "framing": framing,
                "content_encoding": headers.get("content-encoding"),
                "source_ranges": ranges,
                "body": body,
                "complete": complete,
                "reason": reason,
            })
        message_index += 1
        if not complete:
            break
        if next_cursor <= cursor:
            raise ValueError("HTTP parser made no progress")
        cursor = next_cursor
    return bodies, unparsed


def _response_has_no_body(start_line: str) -> bool:
    parts = start_line.split()
    if len(parts) < 2:
        return False
    try:
        status = int(parts[1])
    except ValueError:
        return False
    return 100 <= status < 200 or status in {204, 304}


def extract_payload_sources(
    m01_artifact_path: str | Path,
    output_dir: str | Path,
    *,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> dict[str, Any]:
    input_path = Path(m01_artifact_path)
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    if max_stream_bytes <= 0:
        raise ValueError("max_stream_bytes must be positive")
    m01, m01_sha256 = load_json_artifact_with_sha256(input_path)
    jsonschema.validate(m01, json.loads(M01_SCHEMA.read_text(encoding="utf-8")))
    validate_m01_references(m01)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": {"module": "M01", "artifact_path": str(input_path), "artifact_sha256": m01_sha256,
                   "record_id": m01["id"], "schema_version": m01["schema_version"]},
        "status": "no_http_payloads",
        "parameters": {"max_stream_bytes": max_stream_bytes},
        "sources": [],
        "unparsed_ranges": [],
        "metrics": {"stream_count": len(m01["streams"]), "direction_count": 0,
                    "payload_count": 0, "complete_payload_count": 0, "output_bytes": 0},
        "warnings": [],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        payload_dir = staging / "payloads"
        payload_dir.mkdir()
        for stream in m01["streams"]:
            integrity_limited = stream["reassembly_status"] != "complete" or any(
                stream["analysis"].get(key, 0) for key in ("truncated_packets", "gap_or_loss_packets")
            )
            for direction in stream["directions"]:
                result["metrics"]["direction_count"] += 1
                artifact_path = _resolve(input_path, direction["artifact_ref"])
                if not artifact_path.is_file():
                    raise FileNotFoundError(f"M01 stream artifact does not exist: {artifact_path}")
                if artifact_path.stat().st_size != direction["length"]:
                    raise ValueError(f"M01 stream artifact length mismatch: {artifact_path}")
                raw = artifact_path.read_bytes()
                if sha256_bytes(raw) != direction["sha256"]:
                    raise ValueError(f"M01 stream artifact SHA-256 mismatch: {artifact_path}")
                if len(raw) > max_stream_bytes:
                    result["unparsed_ranges"].append({"stream_id": stream["id"], "direction": direction["direction"],
                                                       "start": 0, "end": len(raw), "reason": "STREAM_EXCEEDS_MAX_BYTES"})
                    continue
                bodies, unparsed = _http_bodies(raw)
                for item in unparsed:
                    result["unparsed_ranges"].append({"stream_id": stream["id"], "direction": direction["direction"], **item})
                for item in bodies:
                    source_id = f"payload-{stream['id']}-{direction['direction']}-{item['message_index']:04d}"
                    body = item.pop("body")
                    parser_complete = bool(item.pop("complete"))
                    reason = item.pop("reason")
                    complete = parser_complete and not integrity_limited
                    target = payload_dir / f"{source_id}.bin"
                    target.write_bytes(body)
                    limitations = []
                    if reason:
                        limitations.append(str(reason))
                    if integrity_limited:
                        limitations.append("M01 stream reassembly declared incomplete transport evidence.")
                    result["sources"].append({
                        "source_id": source_id, "protocol": "http", "stream_id": stream["id"],
                        "flow_id": stream["flow_id"], "direction": direction["direction"],
                        "recognition_basis": "strict_http_start_line_and_framing_headers", **item,
                        "source_artifact": {"artifact_path": str(artifact_path), "artifact_sha256": direction["sha256"],
                                            "length": direction["length"]},
                        "output": {"artifact_ref": target.relative_to(staging).as_posix(),
                                   "sha256": sha256_bytes(body), "length": len(body)},
                        "completeness": "complete" if complete else "partial",
                        "limitations": limitations,
                    })
                    result["metrics"]["output_bytes"] += len(body)
        result["metrics"]["payload_count"] = len(result["sources"])
        result["metrics"]["complete_payload_count"] = sum(
            item["completeness"] == "complete" for item in result["sources"]
        )
        if result["sources"]:
            result["status"] = "ok" if result["metrics"]["complete_payload_count"] == len(result["sources"]) and not result["unparsed_ranges"] else "partial"
        elif result["unparsed_ranges"]:
            result["warnings"].append("No complete HTTP body source was extracted from the admitted stream bytes.")
        jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
        (staging / "payload_sources.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract HTTP body payload sources from every M01 TCP direction.")
    parser.add_argument("m01_artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-stream-bytes", type=int, default=DEFAULT_MAX_STREAM_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        extract_payload_sources(args.m01_artifact, args.output_dir, max_stream_bytes=args.max_stream_bytes)
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"payload-sources: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "payload_sources.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

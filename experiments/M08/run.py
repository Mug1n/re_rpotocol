#!/usr/bin/env python3
"""M08 bounded, evidence-preserving byte recovery."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shutil
import sys
import tempfile
import zlib
from collections import deque
from pathlib import Path
from typing import Any, NamedTuple

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import load_json_artifact_with_sha256, sha256_file, validate_m01_references

OUTPUT_SCHEMA = ROOT / "research" / "M08-recovery" / "recovery.schema.json"
PAYLOAD_SOURCES_SCHEMA = ROOT / "research" / "M08-recovery" / "payload-sources.schema.json"
M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
SCHEMA_VERSION = "0.1"
HEX_PATTERN = re.compile(rb"(?:[0-9A-Fa-f]{2}\s*)+")
BASE64_PATTERN = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024

# Protocol layouts a caller may declare for an input it already knows to be
# encrypted. Everything here comes from the protocol document; none of it is
# inferred from the bytes, so the declared regions are labelled
# ``protocol_declared`` wherever they surface.
DECLARED_PROTOCOL_LAYOUTS: dict[str, dict[str, Any]] = {
    "tls": {
        "layout_id": "tls_record_header_5b",
        "header_size": 5,
        "length_offset": 3,
        "length_width": 2,
        "byteorder": "big",
        "content_types": {
            0x14: "change_cipher_spec",
            0x15: "alert",
            0x16: "handshake",
            0x17: "application_data",
        },
        "handshake_types": {
            0x01: "ClientHello",
            0x02: "ServerHello",
            0x08: "EncryptedExtensions",
            0x0B: "Certificate",
            0x14: "Finished",
        },
        "unprotected_content_types": (0x14,),
        "unprotected_until_protection_boundary": 0x16,
        "protection_boundary_content_type": 0x17,
    },
}


def _declared_plaintext_regions(
    data: bytes, protocol: str | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
    """Split a declared-layout stream into unprotected and protected regions.

    Returns ``(plaintext, protected)`` when the declared layout tiles the whole
    input exactly, and ``None`` otherwise so the caller keeps its refusal
    behaviour. Every decision below reads a field of a record header, which the
    declared layout marks unprotected; no protected byte is used to classify
    anything, and nothing is decrypted.
    """
    layout = DECLARED_PROTOCOL_LAYOUTS.get(protocol or "")
    if layout is None or not data:
        return None
    header = layout["header_size"]
    records: list[tuple[int, int, int, int]] = []
    offset = 0
    while offset < len(data):
        if offset + header > len(data):
            return None
        end = offset + header + int.from_bytes(
            data[offset + layout["length_offset"]:offset + layout["length_width"] + layout["length_offset"]],
            layout["byteorder"],
        )
        if end > len(data):
            return None
        records.append((offset, end, data[offset], end - offset - header))
        offset = end
    if len(records) < 2:
        return None

    plaintext: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    past_boundary = False
    for index, (start, end, content_type, declared_length) in enumerate(records):
        common = {
            "record_index": index,
            "content_type": content_type,
            "content_type_name": layout["content_types"].get(content_type),
            "declared_length": declared_length,
        }
        plaintext.append({**common, "role": "record_header", "start": start, "end": start + header})
        if end == start + header:
            pass
        elif content_type in layout["unprotected_content_types"]:
            plaintext.append({**common, "role": "change_cipher_spec", "start": start + header, "end": end})
        elif content_type == layout["unprotected_until_protection_boundary"] and not past_boundary:
            handshake_type = data[start + header]
            plaintext.append({
                **common, "role": "handshake_plaintext", "start": start + header, "end": end,
                "handshake_type": handshake_type,
                "handshake_type_name": layout["handshake_types"].get(handshake_type),
            })
        else:
            protected.append({**common, "role": "protected", "start": start + header, "end": end})
        if content_type == layout["protection_boundary_content_type"]:
            past_boundary = True
    return plaintext, protected


def _declared_region_groups(protocol: str, plaintext: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group declared plaintext regions by role, in a stable order."""
    layout_id = DECLARED_PROTOCOL_LAYOUTS[protocol]["layout_id"]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for region in plaintext:
        grouped.setdefault(region["role"], []).append(region)
    groups: list[dict[str, Any]] = []
    for role in ("record_header", "handshake_plaintext", "change_cipher_spec"):
        regions = grouped.get(role)
        if not regions:
            continue
        total = sum(region["end"] - region["start"] for region in regions)
        evidence = [
            f"declared layout {layout_id}: role {role}, {len(regions)} region(s), {total} bytes; "
            "the plaintext/protected split is declared by the caller, not inferred from the bytes"
        ]
        for region in regions:
            line = (
                f"record #{region['record_index']} [{region['start']}, {region['end']}) "
                f"content_type=0x{region['content_type']:02x}"
                f"{' ' + region['content_type_name'] if region['content_type_name'] else ''}"
            )
            if role == "handshake_plaintext":
                line += (
                    f" handshake_type=0x{region['handshake_type']:02x}"
                    f"{' ' + region['handshake_type_name'] if region['handshake_type_name'] else ''}"
                )
            evidence.append(line + f" declared_length={region['declared_length']}")
        groups.append({
            "role": role,
            "regions": regions,
            "ranges": [{"start": region["start"], "end": region["end"]} for region in regions],
            "evidence": evidence,
        })
    return groups


def _decompress_limited(data: bytes, *, wbits: int, max_output_bytes: int, max_ratio: float) -> bytes:
    is_gzip = wbits == 31
    remaining = data
    output = bytearray()
    while remaining:
        decoder = zlib.decompressobj(wbits)
        member = decoder.decompress(remaining, max_output_bytes + 1 - len(output))
        output.extend(member)
        if len(output) > max_output_bytes or decoder.unconsumed_tail:
            raise OverflowError("MAX_OUTPUT_BYTES")
        output.extend(decoder.flush(max_output_bytes + 1 - len(output)))
        if len(output) > max_output_bytes:
            raise OverflowError("MAX_OUTPUT_BYTES")
        if not decoder.eof:
            raise ValueError("INVALID_COMPRESSED_STREAM")
        trailing = decoder.unused_data
        if not trailing:
            break
        if not is_gzip or not trailing.startswith(b"\x1f\x8b"):
            raise ValueError("TRAILING_DATA")
        remaining = trailing
    if data and len(output) / len(data) > max_ratio:
        raise OverflowError("MAX_INFLATION_RATIO")
    return bytes(output)


def _text_operation(data: bytes, min_printable_length: int) -> str | None:
    candidates: list[tuple[str, str]] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            candidates.append(("utf16", data.decode("utf-16")))
        except UnicodeDecodeError:
            pass
    try:
        candidates.append(("utf8", data.decode("utf-8")))
    except UnicodeDecodeError:
        pass
    for operation, text in candidates:
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if len(text) >= min_printable_length and printable == len(text):
            return operation
    return None


def _step(operation: str, before: bytes, after: bytes, validation: str) -> dict[str, Any]:
    return {
        "operation": operation,
        "input_length": len(before),
        "output_length": len(after),
        "parameters": {},
        "validation": validation,
    }


class _Candidate(NamedTuple):
    """One admitted recovery, before it is staged and written.

    ``source_ranges`` overrides the recorded provenance when the recovery is not
    the whole input (declared regions are disjoint); ``evidence`` overrides the
    generic validation line.
    """

    recovered: bytes
    chain: list[dict[str, Any]]
    basis: str
    media_type: str | None
    source_ranges: list[dict[str, int]] | None = None
    evidence: list[str] | None = None


def _publish(
    result: dict[str, Any],
    destination: Path,
    data: bytes,
    source_sha256: str,
    source_ref: dict[str, Any],
    candidates: list[_Candidate],
    admitted_output_hashes: dict[str, int],
    *,
    source_ranges: list[dict[str, int]] | None,
    source_context: dict[str, Any] | None,
    max_artifacts: int,
    source_completeness: str,
) -> dict[str, Any]:
    """Stage the admitted artifacts and publish recovery.json atomically."""
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        recovered_dir = staging / "recovered"
        recovered_dir.mkdir()
        unique_chains: set[tuple[str, tuple[str, ...]]] = set()
        artifact_refs: dict[str, str] = {}
        for candidate in candidates:
            operations = tuple(step["operation"] for step in candidate.chain)
            output_sha = hashlib.sha256(candidate.recovered).hexdigest()
            identity = (output_sha, operations)
            if identity in unique_chains or len(result["recoveries"]) >= max_artifacts:
                continue
            unique_chains.add(identity)
            recovery_id = f"m08-{source_sha256[:12]}-{len(result['recoveries']):04d}"
            artifact_ref = artifact_refs.get(output_sha)
            if artifact_ref is None:
                artifact = recovered_dir / f"{recovery_id}.bin"
                artifact.write_bytes(candidate.recovered)
                artifact_ref = artifact.relative_to(staging).as_posix()
                artifact_refs[output_sha] = artifact_ref
            ranges = candidate.source_ranges if candidate.source_ranges is not None else source_ranges
            recovery = {
                "recovery_id": recovery_id,
                "source_ref": source_ref,
                "source_range": (
                    {"start": ranges[0]["start"], "end": ranges[-1]["end"]}
                    if candidate.source_ranges else {"start": 0, "end": len(data)}
                ),
                "basis": candidate.basis,
                "transformation_chain": candidate.chain,
                "output": {"artifact_ref": artifact_ref, "sha256": output_sha,
                           "length": len(candidate.recovered), "media_type": candidate.media_type},
                "completeness": (
                    "partial" if source_completeness == "partial"
                    else "complete" if candidate.basis in ("validated_magic", "protocol_declared")
                    else "candidate"
                ),
                "evidence": candidate.evidence
                or ["strict validation completed for every recorded transformation"],
            }
            if ranges is not None:
                recovery["source_ranges"] = ranges
            if source_context is not None:
                recovery["source_context"] = source_context
            result["recoveries"].append(recovery)
        if result["recoveries"]:
            result["status"] = "partial" if result["failed_attempts"] or result["skipped_sources"] else "ok"
        result["metrics"] = {
            "recovery_count": len(result["recoveries"]),
            "failed_attempt_count": len(result["failed_attempts"]),
            "skipped_source_count": len(result["skipped_sources"]),
            "output_bytes": sum(admitted_output_hashes.values()),
        }
        jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
        (staging / "recovery.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def analyze_recovery(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    expected_sha256: str | None = None,
    source_module: str = "direct",
    source_record_id: str | None = None,
    encrypted_protocol: str | None = None,
    unsupported_content_encoding: str | None = None,
    source_basis: str = "strict_candidate",
    source_completeness: str = "complete",
    source_ranges: list[dict[str, int]] | None = None,
    source_context: dict[str, Any] | None = None,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_depth: int = 3,
    max_output_bytes: int = 8 * 1024 * 1024,
    max_inflation_ratio: float = 100.0,
    max_artifacts: int = 32,
    min_printable_length: int = 4,
) -> dict[str, Any]:
    source = Path(input_path)
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    if source_basis not in {"strict_candidate", "protocol_declared"}:
        raise ValueError("source_basis must be strict_candidate or protocol_declared")
    if source_completeness not in {"complete", "partial"}:
        raise ValueError("source_completeness must be complete or partial")
    if max_input_bytes <= 0 or max_depth < 0 or max_output_bytes <= 0 or max_inflation_ratio <= 0 or max_artifacts <= 0 or min_printable_length <= 0:
        raise ValueError("recovery limits must be positive and max_depth non-negative")
    try:
        if source.stat().st_size > max_input_bytes:
            raise ValueError("INPUT_EXCEEDS_MAX_BYTES")
        with source.open("rb") as handle:
            data = handle.read(max_input_bytes + 1)
    except FileNotFoundError:
        raise FileNotFoundError(f"input does not exist: {source}")
    if len(data) > max_input_bytes:
        raise ValueError("INPUT_EXCEEDS_MAX_BYTES")
    source_sha256 = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and source_sha256 != expected_sha256:
        raise ValueError(f"source SHA-256 mismatch: expected {expected_sha256}, got {source_sha256}")
    source_ref = {
        "module": source_module,
        "artifact_path": str(source),
        "artifact_sha256": source_sha256,
        "record_id": source_record_id or source.name,
    }
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": source_ref,
        "status": "empty" if not data else "no_recoverable_content",
        "parameters": {
            "max_input_bytes": max_input_bytes,
            "max_depth": max_depth,
            "max_output_bytes": max_output_bytes,
            "max_inflation_ratio": max_inflation_ratio,
            "max_artifacts": max_artifacts,
            "min_printable_length": min_printable_length,
            "enabled_decoders": ["utf8", "utf16", "hex", "base64", "gzip", "zlib"],
            "source_basis": source_basis,
            "source_completeness": source_completeness,
        },
        "recoveries": [],
        "failed_attempts": [],
        "skipped_sources": [],
        "metrics": {"recovery_count": 0, "failed_attempt_count": 0, "skipped_source_count": 0, "output_bytes": 0},
        "warnings": ["Successful decoding or decompression does not establish application semantics."],
    }
    candidates: list[_Candidate] = []
    admitted_output_hashes: dict[str, int] = {}
    admitted_output_bytes = 0

    def admit_candidate(
        recovered: bytes,
        chain: list[dict[str, Any]],
        basis: str,
        media_type: str | None,
        operation: str,
        span: dict[str, int] | None = None,
        evidence: list[str] | None = None,
    ) -> bool:
        nonlocal admitted_output_bytes
        if len(candidates) >= max_artifacts:
            return False
        output_sha = hashlib.sha256(recovered).hexdigest()
        if output_sha not in admitted_output_hashes:
            if admitted_output_bytes + len(recovered) > max_output_bytes:
                result["failed_attempts"].append({
                    "source_ref": source_ref,
                    "operation": operation,
                    "reason_code": "TOTAL_OUTPUT_BYTES",
                })
                return False
            admitted_output_hashes[output_sha] = len(recovered)
            admitted_output_bytes += len(recovered)
        candidates.append(_Candidate(recovered, chain, basis, media_type, span, evidence))
        return True

    declared = (
        _declared_plaintext_regions(data, encrypted_protocol)
        if encrypted_protocol is not None and not unsupported_content_encoding
        else None
    )
    if unsupported_content_encoding or (encrypted_protocol is not None and declared is None):
        skipped = {
            "source_ref": source_ref,
            "reason_code": (
                "ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL" if encrypted_protocol
                else "UNSUPPORTED_CONTENT_ENCODING"
            ),
            "detail": (
                f"{encrypted_protocol.upper()} content was not treated as plaintext without explicit decryption material."
                if encrypted_protocol else
                f"HTTP Content-Encoding {unsupported_content_encoding!r} is not supported by M08."
            ),
        }
        if source_ranges is not None:
            skipped["source_ranges"] = source_ranges
        if source_context is not None:
            skipped["source_context"] = source_context
        result["skipped_sources"].append(skipped)
    elif declared is not None:
        assert encrypted_protocol is not None
        plaintext_regions, protected_regions = declared
        destination.parent.mkdir(parents=True, exist_ok=True)
        result["warnings"].append(
            "Declared plaintext regions follow the protocol layout supplied by the caller; the "
            "plaintext/protected split is not inferred from the bytes, and protected bytes are refused."
        )
        result["skipped_sources"].append({
            "source_ref": source_ref,
            "reason_code": "DECLARED_PROTECTED_REGION",
            "detail": (
                f"{len(protected_regions)} declared-protected region(s), "
                f"{sum(region['end'] - region['start'] for region in protected_regions)} bytes, "
                "were refused: the payloads past the protection boundary are encrypted and no "
                "decryption material was supplied."
            ),
            "source_ranges": [
                {"start": region["start"], "end": region["end"]} for region in protected_regions
            ],
        })
        for group in _declared_region_groups(encrypted_protocol, plaintext_regions):
            recovered = b"".join(data[region["start"]:region["end"]] for region in group["regions"])
            admit_candidate(
                recovered,
                [{
                    "operation": "declared_plaintext_region",
                    "input_length": len(recovered),
                    "output_length": len(recovered),
                    "parameters": {
                        "role": group["role"],
                        "declared_layout": DECLARED_PROTOCOL_LAYOUTS[encrypted_protocol]["layout_id"],
                    },
                    "validation": "declared_unprotected_region",
                }],
                "protocol_declared",
                None,
                "declared_plaintext_region",
                group["ranges"],
                group["evidence"],
            )
        return _publish(
            result, destination, data, source_sha256, source_ref, candidates, admitted_output_hashes,
            source_ranges=source_ranges, source_context=source_context,
            max_artifacts=max_artifacts, source_completeness=source_completeness,
        )
    elif data:
        destination.parent.mkdir(parents=True, exist_ok=True)
        pending = deque([(data, [], source_basis)])
        seen = {hashlib.sha256(data).hexdigest()}

        while pending and len(candidates) < max_artifacts:
            current, chain, basis = pending.popleft()
            if len(chain) >= max_depth:
                result["failed_attempts"].append({"source_ref": source_ref, "operation": "decode", "reason_code": "MAX_RECURSION_DEPTH"})
                continue
            text = _text_operation(current, min_printable_length)
            if text is not None:
                admit_candidate(
                    current,
                    chain + [_step(text, current, current, "strict_decode")],
                    basis,
                    f"text/plain; charset={text}",
                    text,
                )
            transforms: list[tuple[str, bytes, str]] = []
            compact = b"".join(current.split())
            if len(compact) >= 2 and len(compact) % 2 == 0 and HEX_PATTERN.fullmatch(current):
                try:
                    transforms.append(("hex", bytes.fromhex(compact.decode("ascii")), "strict_alphabet_and_length"))
                except (ValueError, UnicodeDecodeError):
                    result["failed_attempts"].append({"source_ref": source_ref, "operation": "hex", "reason_code": "INVALID_HEX"})
            if len(compact) >= 4 and re.fullmatch(rb"[A-Za-z0-9+/=]+", compact):
                if len(compact) % 4 == 0 and BASE64_PATTERN.fullmatch(compact):
                    try:
                        transforms.append(("base64", base64.b64decode(compact, validate=True), "strict_alphabet_and_padding"))
                    except binascii.Error:
                        result["failed_attempts"].append({"source_ref": source_ref, "operation": "base64", "reason_code": "INVALID_BASE64"})
                elif b"=" in compact:
                    result["failed_attempts"].append({"source_ref": source_ref, "operation": "base64", "reason_code": "INVALID_BASE64"})
            for operation, magic, wbits in (("gzip", b"\x1f\x8b", 31), ("zlib", b"\x78", 15)):
                if current.startswith(magic):
                    try:
                        transforms.append((operation, _decompress_limited(current, wbits=wbits, max_output_bytes=max_output_bytes, max_ratio=max_inflation_ratio), "container_integrity"))
                    except OverflowError as exc:
                        result["failed_attempts"].append({"source_ref": source_ref, "operation": operation, "reason_code": str(exc)})
                    except ValueError as exc:
                        result["failed_attempts"].append({"source_ref": source_ref, "operation": operation, "reason_code": str(exc)})
                    except zlib.error:
                        result["failed_attempts"].append({"source_ref": source_ref, "operation": operation, "reason_code": "INVALID_COMPRESSED_STREAM"})
            for operation, transformed, validation in transforms:
                next_basis = (
                    basis if basis == "protocol_declared"
                    else "validated_magic" if operation in ("gzip", "zlib")
                    else basis
                )
                next_chain = chain + [_step(operation, current, transformed, validation)]
                if not admit_candidate(transformed, next_chain, next_basis, None, operation):
                    continue
                digest = hashlib.sha256(transformed).hexdigest()
                if digest not in seen:
                    seen.add(digest)
                    pending.append((transformed, next_chain, next_basis))

        return _publish(
            result, destination, data, source_sha256, source_ref, candidates, admitted_output_hashes,
            source_ranges=source_ranges, source_context=source_context,
            max_artifacts=max_artifacts, source_completeness=source_completeness,
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        result["metrics"] = {"recovery_count": 0, "failed_attempt_count": len(result["failed_attempts"]), "skipped_source_count": len(result["skipped_sources"]), "output_bytes": 0}
        jsonschema.validate(result, json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8")))
        (staging / "recovery.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _resolve_reference(parent_artifact: Path, reference: str) -> Path:
    path = Path(reference)
    if path.is_absolute():
        return path
    nearby = parent_artifact.parent / path
    return nearby if nearby.is_file() else Path.cwd() / path


def analyze_payload_source(
    payload_sources_path: str | Path,
    source_id: str,
    output_dir: str | Path,
    **parameters: Any,
) -> dict[str, Any]:
    """Recover one declared HTTP body after revalidating its complete provenance chain."""
    manifest_path = Path(payload_sources_path)
    manifest, manifest_sha256 = load_json_artifact_with_sha256(manifest_path)
    jsonschema.validate(
        manifest, json.loads(PAYLOAD_SOURCES_SCHEMA.read_text(encoding="utf-8"))
    )
    m01_ref = manifest["source"]
    m01_path = _resolve_reference(manifest_path, m01_ref["artifact_path"])
    m01, _ = load_json_artifact_with_sha256(
        m01_path, expected_sha256=m01_ref["artifact_sha256"]
    )
    jsonschema.validate(m01, json.loads(M01_SCHEMA.read_text(encoding="utf-8")))
    validate_m01_references(m01)
    matches = [item for item in manifest["sources"] if item["source_id"] == source_id]
    if len(matches) != 1:
        raise ValueError(f"payload source_id must resolve exactly once: {source_id!r}")
    source = matches[0]
    payload_path = _resolve_reference(manifest_path, source["output"]["artifact_ref"])
    if not payload_path.is_file():
        raise FileNotFoundError(f"payload artifact does not exist: {payload_path}")
    if payload_path.stat().st_size != source["output"]["length"]:
        raise ValueError("payload artifact length mismatch")
    if sha256_file(payload_path) != source["output"]["sha256"]:
        raise ValueError("payload artifact SHA-256 mismatch")
    stream = source["source_artifact"]
    matching_streams = [item for item in m01["streams"] if item["id"] == source["stream_id"]]
    if len(matching_streams) != 1 or matching_streams[0]["flow_id"] != source["flow_id"]:
        raise ValueError("payload source stream/flow does not match referenced M01")
    matching_directions = [
        item for item in matching_streams[0]["directions"]
        if item["direction"] == source["direction"]
    ]
    if len(matching_directions) != 1 or any(
        matching_directions[0][key] != stream[value]
        for key, value in (("sha256", "artifact_sha256"), ("length", "length"))
    ):
        raise ValueError("payload source direction does not match referenced M01")
    stream_path = _resolve_reference(manifest_path, stream["artifact_path"])
    if not stream_path.is_file():
        raise FileNotFoundError(f"source stream artifact does not exist: {stream_path}")
    if stream_path.stat().st_size != stream["length"]:
        raise ValueError("source stream artifact length mismatch")
    if sha256_file(stream_path) != stream["artifact_sha256"]:
        raise ValueError("source stream artifact SHA-256 mismatch")
    stream_bytes = stream_path.read_bytes()
    previous_end = -1
    rebuilt = bytearray()
    for item in source["source_ranges"]:
        start, end = item["start"], item["end"]
        if start > end or start < previous_end or end > len(stream_bytes):
            raise ValueError("payload source ranges are invalid or overlapping")
        rebuilt.extend(stream_bytes[start:end])
        previous_end = end
    if bytes(rebuilt) != payload_path.read_bytes():
        raise ValueError("payload bytes do not match declared source ranges")
    context = {
        "payload_sources_path": str(manifest_path),
        "payload_sources_sha256": manifest_sha256,
        "protocol": source["protocol"],
        "recognition_basis": source["recognition_basis"],
        "stream_id": source["stream_id"],
        "flow_id": source["flow_id"],
        "direction": source["direction"],
        "message_index": source["message_index"],
        "framing": source["framing"],
        "content_encoding": source["content_encoding"],
    }
    encoding = (source["content_encoding"] or "identity").strip().lower()
    supported_encodings = {"identity", "gzip", "x-gzip", "deflate"}
    return analyze_recovery(
        payload_path,
        output_dir,
        expected_sha256=source["output"]["sha256"],
        source_module="payload_sources",
        source_record_id=source["source_id"],
        source_basis="protocol_declared",
        source_completeness=source["completeness"],
        source_ranges=source["source_ranges"],
        source_context=context,
        unsupported_content_encoding=(
            None if encoding in supported_encodings else source["content_encoding"]
        ),
        **parameters,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover strictly validated text, encodings, and compressed content under explicit limits.")
    parser.add_argument("input", type=Path, nargs="?")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--payload-sources", type=Path)
    parser.add_argument("--payload-source-id")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--source-module", default="direct")
    parser.add_argument("--source-record-id")
    parser.add_argument("--encrypted-protocol", choices=("tls", "ssh"))
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-output-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-inflation-ratio", type=float, default=100.0)
    parser.add_argument("--max-artifacts", type=int, default=32)
    parser.add_argument("--min-printable-length", type=int, default=4)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        common = {
            "max_input_bytes": args.max_input_bytes, "max_depth": args.max_depth,
            "max_output_bytes": args.max_output_bytes,
            "max_inflation_ratio": args.max_inflation_ratio,
            "max_artifacts": args.max_artifacts,
            "min_printable_length": args.min_printable_length,
        }
        if args.payload_sources is not None or args.payload_source_id is not None:
            if args.input is not None or args.payload_sources is None or not args.payload_source_id:
                raise ValueError("use either input or --payload-sources with --payload-source-id")
            analyze_payload_source(
                args.payload_sources, args.payload_source_id, args.output_dir, **common
            )
        else:
            if args.input is None:
                raise ValueError("input is required for direct recovery")
            analyze_recovery(
                args.input, args.output_dir, expected_sha256=args.expected_sha256,
                source_module=args.source_module, source_record_id=args.source_record_id,
                encrypted_protocol=args.encrypted_protocol, **common,
            )
    except (FileNotFoundError, FileExistsError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m08: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "recovery.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

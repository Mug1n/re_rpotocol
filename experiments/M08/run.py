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
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUTPUT_SCHEMA = ROOT / "research" / "M08-recovery" / "recovery.schema.json"
SCHEMA_VERSION = "0.1"
HEX_PATTERN = re.compile(rb"(?:[0-9A-Fa-f]{2}\s*)+")
BASE64_PATTERN = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024


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


def analyze_recovery(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    expected_sha256: str | None = None,
    source_module: str = "direct",
    source_record_id: str | None = None,
    encrypted_protocol: str | None = None,
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
        },
        "recoveries": [],
        "failed_attempts": [],
        "skipped_sources": [],
        "metrics": {"recovery_count": 0, "failed_attempt_count": 0, "skipped_source_count": 0, "output_bytes": 0},
        "warnings": ["Successful decoding or decompression does not establish application semantics."],
    }
    if encrypted_protocol:
        result["skipped_sources"].append({
            "source_ref": source_ref,
            "reason_code": "ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL",
            "detail": f"{encrypted_protocol.upper()} content was not treated as plaintext without explicit decryption material.",
        })
    elif data:
        destination.parent.mkdir(parents=True, exist_ok=True)
        pending = deque([(data, [], "strict_candidate")])
        seen = {hashlib.sha256(data).hexdigest()}
        candidates: list[tuple[bytes, list[dict[str, Any]], str, str | None]] = []
        admitted_output_hashes: dict[str, int] = {}
        admitted_output_bytes = 0

        def admit_candidate(
            recovered: bytes,
            chain: list[dict[str, Any]],
            basis: str,
            media_type: str | None,
            operation: str,
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
            candidates.append((recovered, chain, basis, media_type))
            return True

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
                next_basis = "validated_magic" if operation in ("gzip", "zlib") else basis
                next_chain = chain + [_step(operation, current, transformed, validation)]
                if not admit_candidate(transformed, next_chain, next_basis, None, operation):
                    continue
                digest = hashlib.sha256(transformed).hexdigest()
                if digest not in seen:
                    seen.add(digest)
                    pending.append((transformed, next_chain, next_basis))

        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
        try:
            recovered_dir = staging / "recovered"
            recovered_dir.mkdir()
            unique_chains: set[tuple[str, tuple[str, ...]]] = set()
            artifact_refs: dict[str, str] = {}
            for recovered, chain, basis, media_type in candidates:
                operations = tuple(step["operation"] for step in chain)
                output_sha = hashlib.sha256(recovered).hexdigest()
                identity = (output_sha, operations)
                if identity in unique_chains or len(result["recoveries"]) >= max_artifacts:
                    continue
                unique_chains.add(identity)
                recovery_id = f"m08-{source_sha256[:12]}-{len(result['recoveries']):04d}"
                artifact_ref = artifact_refs.get(output_sha)
                if artifact_ref is None:
                    artifact = recovered_dir / f"{recovery_id}.bin"
                    artifact.write_bytes(recovered)
                    artifact_ref = artifact.relative_to(staging).as_posix()
                    artifact_refs[output_sha] = artifact_ref
                result["recoveries"].append({
                    "recovery_id": recovery_id,
                    "source_ref": source_ref,
                    "source_range": {"start": 0, "end": len(data)},
                    "basis": basis,
                    "transformation_chain": chain,
                    "output": {"artifact_ref": artifact_ref, "sha256": output_sha, "length": len(recovered), "media_type": media_type},
                    "completeness": "complete" if basis in ("validated_magic", "protocol_declared") else "candidate",
                    "evidence": ["strict validation completed for every recorded transformation"],
                })
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover strictly validated text, encodings, and compressed content under explicit limits.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
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
        analyze_recovery(args.input, args.output_dir, expected_sha256=args.expected_sha256, source_module=args.source_module, source_record_id=args.source_record_id, encrypted_protocol=args.encrypted_protocol, max_input_bytes=args.max_input_bytes, max_depth=args.max_depth, max_output_bytes=args.max_output_bytes, max_inflation_ratio=args.max_inflation_ratio, max_artifacts=args.max_artifacts, min_printable_length=args.min_printable_length)
    except (FileNotFoundError, FileExistsError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m08: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "recovery.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""M07 standard-protocol observations backed by explicit TShark fields."""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import load_json_artifact_with_sha256, validate_m01_references


M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
OUTPUT_SCHEMA = ROOT / "research" / "M07-standard-protocols" / "protocols.schema.json"
SCHEMA_VERSION = "0.1"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CAPTURE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_OBSERVATIONS = 10_000
DEFAULT_MAX_TSHARK_OUTPUT_BYTES = 32 * 1024 * 1024
PROTOCOL_FIELDS = {
    "http": ("http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_type"),
    "smtp": ("smtp.req.command", "smtp.response.code"),
    "pop": ("pop.request.command", "pop.response.indicator"),
    "imap": ("imap.request", "imap.response"),
    "ftp": ("ftp.request.command", "ftp.response.code"),
    "tls": ("tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions_server_name"),
    "ssh": ("ssh.protocol", "ssh.message_code"),
    "dns": ("dns.qry.name", "dns.qry.type", "dns.flags.response"),
}
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _tshark_fields() -> tuple[str, ...]:
    return (
        "frame.number",
        "frame.protocols",
        *(field for fields in PROTOCOL_FIELDS.values() for field in fields),
    )


def _first(layers: dict[str, Any], field: str) -> Any:
    value = layers.get(field)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _resolve_source(artifact_path: Path, source_value: str) -> Path:
    source = Path(source_value)
    if source.is_absolute():
        return source
    artifact_relative = artifact_path.parent / source
    if artifact_relative.is_file():
        return artifact_relative
    working_relative = Path.cwd() / source
    return working_relative if working_relative.is_file() else artifact_relative


def _source_reference(path: Path, artifact: dict[str, Any], artifact_sha256: str) -> dict[str, Any]:
    return {
        "module": "M01",
        "artifact_path": str(path),
        "artifact_sha256": artifact_sha256,
        "record_id": artifact["id"],
        "schema_version": artifact["schema_version"],
    }


def _base_result(
    path: Path,
    artifact: dict[str, Any],
    artifact_sha256: str,
    decode_as: list[str],
    display_filter: str | None,
    timeout_seconds: float,
    max_capture_bytes: int,
    max_observations: int,
    max_tshark_output_bytes: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source": _source_reference(path, artifact, artifact_sha256),
        "status": "unknown",
        "parameters": {
            "decode_as": decode_as,
            "display_filter": display_filter,
            "timeout_seconds": timeout_seconds,
            "max_capture_bytes": max_capture_bytes,
            "max_observations": max_observations,
            "max_tshark_output_bytes": max_tshark_output_bytes,
        },
        "tool": {"path": None, "version": None},
        "observations": [],
        "unknown_scopes": [],
        "artifacts": [],
        "metrics": {"observation_count": 0, "unknown_scope_count": 0, "processed_record_count": 0, "truncated": False},
        "warnings": [],
    }


def _write_result(destination: Path, result: dict[str, Any]) -> dict[str, Any]:
    schema = json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(result, schema)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "protocols.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return result


def _degrade(
    result: dict[str, Any],
    *,
    status: str,
    scope_id: str,
    reason_code: str,
    warning: str,
    truncated: bool = False,
) -> None:
    result["status"] = status
    result["observations"] = []
    result["unknown_scopes"] = [{"scope_type": "input", "scope_id": scope_id, "reason_code": reason_code}]
    result["warnings"] = [warning]
    result["metrics"].update(
        {"observation_count": 0, "unknown_scope_count": 1, "processed_record_count": 0, "truncated": truncated}
    )


def _decode_as_targets(rules: Sequence[str]) -> tuple[list[str], set[str]]:
    normalized: list[str] = []
    targets: set[str] = set()
    for raw_rule in rules:
        rule = str(raw_rule).strip()
        if "," not in rule:
            raise ValueError(f"invalid Decode As rule: {raw_rule!r}")
        selector, target = rule.rsplit(",", 1)
        target = target.strip().lower()
        if not selector.strip() or target not in PROTOCOL_FIELDS:
            raise ValueError(f"invalid or unsupported Decode As target: {raw_rule!r}")
        normalized.append(f"{selector.strip()},{target}")
        targets.add(target)
    return normalized, targets


def _snapshot_capture(source: Path, snapshot: Path, expected_sha256: str, max_bytes: int) -> bool:
    digest = hashlib.sha256()
    copied = 0
    with source.open("rb") as source_handle, snapshot.open("xb") as snapshot_handle:
        while chunk := source_handle.read(min(1024 * 1024, max_bytes - copied + 1)):
            copied += len(chunk)
            if copied > max_bytes:
                snapshot_handle.close()
                snapshot.unlink(missing_ok=True)
                return False
            digest.update(chunk)
            snapshot_handle.write(chunk)
    if digest.hexdigest() != expected_sha256:
        snapshot.unlink(missing_ok=True)
        raise ValueError("M01 source SHA-256 mismatch")
    return True


def _source_sha256(source: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _records_from_stream(handle: Any) -> Any:
    first = handle.read(1)
    if not first:
        return
    if first == "[":
        # Compatibility for injected runners that still return the earlier JSON fixture.
        try:
            packets = json.loads(first + handle.read())
        except json.JSONDecodeError as exc:
            raise RuntimeError("tshark returned invalid JSON") from exc
        if not isinstance(packets, list):
            raise RuntimeError("tshark returned invalid JSON packet root")
        for raw in packets:
            layers = raw.get("_source", {}).get("layers", {})
            yield layers
        return
    first_line = first + handle.readline()
    rows = csv.reader(itertools.chain([first_line], handle), delimiter="\t", quotechar='"')
    fields = _tshark_fields()
    for row in rows:
        yield {field: row[index] for index, field in enumerate(fields) if index < len(row) and row[index] != ""}


def analyze_protocols(
    input_artifact: str | Path,
    output_dir: str | Path,
    *,
    tshark_path: str | Path | None = None,
    decode_as: Sequence[str] = (),
    display_filter: str | None = None,
    runner: Runner = subprocess.run,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    max_observations: int = DEFAULT_MAX_OBSERVATIONS,
    max_tshark_output_bytes: int = DEFAULT_MAX_TSHARK_OUTPUT_BYTES,
) -> dict[str, Any]:
    artifact_path = Path(input_artifact)
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    if timeout_seconds <= 0 or max_capture_bytes <= 0 or max_observations <= 0 or max_tshark_output_bytes <= 0:
        raise ValueError("timeout and extraction budgets must be greater than zero")
    artifact, artifact_sha256 = load_json_artifact_with_sha256(artifact_path)
    jsonschema.validate(artifact, json.loads(M01_SCHEMA.read_text(encoding="utf-8")))
    validate_m01_references(artifact)
    source = _resolve_source(artifact_path, artifact["path"])
    if not source.is_file():
        raise FileNotFoundError(f"M01 source does not exist: {source}")
    if _source_sha256(source) != artifact["sha256"]:
        raise ValueError("M01 source SHA-256 mismatch")
    normalized_decode_as, decode_as_targets = _decode_as_targets(decode_as)
    result = _base_result(
        artifact_path,
        artifact,
        artifact_sha256,
        normalized_decode_as,
        display_filter,
        timeout_seconds,
        max_capture_bytes,
        max_observations,
        max_tshark_output_bytes,
    )
    if artifact["format"] not in ("pcap", "pcapng"):
        result["status"] = "not_applicable"
        result["unknown_scopes"] = [{"scope_type": "input", "scope_id": artifact["id"], "reason_code": "CAPTURE_METADATA_ABSENT"}]
        result["warnings"] = ["Raw bytes are not wrapped in synthetic network headers for protocol identification."]
        result["metrics"]["unknown_scope_count"] = 1
        return _write_result(destination, result)

    executable = Path(tshark_path) if tshark_path is not None else Path(shutil.which("tshark") or "")
    if runner is subprocess.run and (not str(executable) or not executable.is_file()):
        result["status"] = "tool_unavailable"
        result["unknown_scopes"] = [{"scope_type": "input", "scope_id": artifact["id"], "reason_code": "TSHARK_UNAVAILABLE"}]
        result["warnings"] = ["TShark is unavailable; no protocol observations were fabricated."]
        result["metrics"]["unknown_scope_count"] = 1
        return _write_result(destination, result)

    run_options = {"capture_output": True, "text": True, "check": False, "timeout": timeout_seconds}
    packet_ids_by_frame = {item["index"] + 1: item["id"] for item in artifact["packets"]}
    observations: list[dict[str, Any]] = []
    record_count = 0
    truncated = False
    with tempfile.TemporaryDirectory(prefix=".m07-private-", dir=artifact_path.parent) as private_dir_value:
        private_dir = Path(private_dir_value)
        snapshot = private_dir / f"capture{source.suffix}"
        if not _snapshot_capture(source, snapshot, artifact["sha256"], max_capture_bytes):
            _degrade(result, status="partial", scope_id=artifact["id"], reason_code="CAPTURE_BYTES_LIMIT",
                     warning="Capture exceeded max_capture_bytes before verification; TShark was not invoked.", truncated=True)
            return _write_result(destination, result)

        try:
            version_result = runner([str(executable), "-v"], **run_options)
        except subprocess.TimeoutExpired:
            _degrade(result, status="tool_unavailable", scope_id=artifact["id"], reason_code="TSHARK_TIMEOUT",
                     warning="TShark version check timed out; partial tool output was discarded.")
            return _write_result(destination, result)
        if version_result.returncode != 0:
            raise RuntimeError(f"tshark version check failed: {version_result.stderr.strip()}")
        result["tool"] = {"path": str(executable), "version": version_result.stdout.splitlines()[0].strip()}

        command = [str(executable), "-r", str(snapshot), "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f", "-c", str(max_observations + 1)]
        for field in _tshark_fields():
            command.extend(["-e", field])
        for rule in normalized_decode_as:
            command.extend(["-d", rule])
        if display_filter:
            command.extend(["-Y", display_filter])

        output_path = private_dir / "tshark-fields.tsv"
        try:
            if runner is subprocess.run:
                with output_path.open("x", encoding="utf-8", newline="") as output_handle:
                    completed = runner(command, stdout=output_handle, stderr=subprocess.PIPE, text=True, check=False, timeout=timeout_seconds)
            else:
                completed = runner(command, **run_options)
                output = completed.stdout or ""
                if len(output.encode("utf-8")) > max_tshark_output_bytes:
                    _degrade(result, status="partial", scope_id=artifact["id"], reason_code="TSHARK_OUTPUT_LIMIT",
                             warning="TShark field output exceeded max_tshark_output_bytes and was discarded.", truncated=True)
                    return _write_result(destination, result)
                output_path.write_text(output, encoding="utf-8", newline="")
        except subprocess.TimeoutExpired:
            output_path.unlink(missing_ok=True)
            _degrade(result, status="tool_unavailable", scope_id=artifact["id"], reason_code="TSHARK_TIMEOUT",
                     warning="TShark extraction timed out; partial field output was discarded.")
            return _write_result(destination, result)
        if completed.returncode != 0:
            raise RuntimeError(f"tshark protocol extraction failed: {(completed.stderr or '').strip()}")
        if output_path.stat().st_size > max_tshark_output_bytes:
            _degrade(result, status="partial", scope_id=artifact["id"], reason_code="TSHARK_OUTPUT_LIMIT",
                     warning="TShark field output exceeded max_tshark_output_bytes and was discarded.", truncated=True)
            return _write_result(destination, result)

        with output_path.open("r", encoding="utf-8", newline="") as output_handle:
            for layers in _records_from_stream(output_handle):
                record_count += 1
                if record_count > max_observations:
                    truncated = True
                    break
                try:
                    frame_number = int(_first(layers, "frame.number"))
                except (TypeError, ValueError):
                    raise RuntimeError("tshark packet missing valid frame.number")
                scope_id = packet_ids_by_frame.get(frame_number)
                if scope_id is None:
                    raise RuntimeError(f"tshark frame {frame_number} has no M01 packet reference")
                hierarchy = str(_first(layers, "frame.protocols") or "").split(":")
                for protocol in sorted(set(hierarchy) & PROTOCOL_FIELDS.keys()):
                    evidence = []
                    for field in PROTOCOL_FIELDS[protocol]:
                        value = _first(layers, field)
                        if value is not None:
                            evidence.append({"field": field, "value": str(value)})
                    if not evidence:
                        continue
                    if len(observations) >= max_observations:
                        truncated = True
                        break
                    encrypted = protocol in ("tls", "ssh")
                    observations.append({
                        "observation_id": f"m07-{scope_id}-{protocol}",
                        "scope_type": "packet", "scope_id": scope_id, "protocol": protocol,
                        "recognition_mode": "decode_as" if protocol in decode_as_targets else "dissector",
                        "visibility": "metadata_only" if encrypted else "application_visible",
                        "field_evidence": evidence,
                        "limitations": ([f"{protocol.upper()} metadata does not establish recovered application plaintext without applicable decryption material."] if encrypted else []),
                    })
                if truncated:
                    break
    result["observations"] = sorted(observations, key=lambda item: item["observation_id"])
    if truncated:
        result["status"] = "partial"
        result["unknown_scopes"] = [{"scope_type": "input", "scope_id": artifact["id"], "reason_code": "TSHARK_OBSERVATION_LIMIT"}]
        result["warnings"] = ["TShark records or protocol observations exceeded max_observations; omitted evidence was not inferred."]
    elif observations:
        result["status"] = "ok"
    else:
        result["status"] = "unknown"
        result["unknown_scopes"] = [{"scope_type": "input", "scope_id": artifact["id"], "reason_code": "NO_APPROVED_PROTOCOL_FIELDS"}]
    result["metrics"] = {
        "observation_count": len(observations),
        "unknown_scope_count": len(result["unknown_scopes"]),
        "processed_record_count": min(record_count, max_observations),
        "truncated": truncated,
    }
    return _write_result(destination, result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record standard-protocol observations from an M01 capture artifact.")
    parser.add_argument("input_artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--decode-as", action="append", default=[])
    parser.add_argument("--display-filter")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-capture-bytes", type=int, default=DEFAULT_MAX_CAPTURE_BYTES)
    parser.add_argument("--max-observations", type=int, default=DEFAULT_MAX_OBSERVATIONS)
    parser.add_argument("--max-tshark-output-bytes", type=int, default=DEFAULT_MAX_TSHARK_OUTPUT_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_protocols(
            args.input_artifact,
            args.output_dir,
            tshark_path=args.tshark,
            decode_as=args.decode_as,
            display_filter=args.display_filter,
            timeout_seconds=args.timeout_seconds,
            max_capture_bytes=args.max_capture_bytes,
            max_observations=args.max_observations,
            max_tshark_output_bytes=args.max_tshark_output_bytes,
        )
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, jsonschema.ValidationError) as exc:
        print(f"m07: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "protocols.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

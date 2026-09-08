#!/usr/bin/env python3
"""M07 standard-protocol observations backed by explicit TShark fields."""

from __future__ import annotations

import argparse
import hashlib
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

from experiments.artifact_contracts import load_json_artifact, sha256_file, validate_m01_references


M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
OUTPUT_SCHEMA = ROOT / "research" / "M07-standard-protocols" / "protocols.schema.json"
SCHEMA_VERSION = "0.1"
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


def _source_reference(path: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "module": "M01",
        "artifact_path": str(path),
        "artifact_sha256": sha256_file(path),
        "record_id": artifact["id"],
        "schema_version": artifact["schema_version"],
    }


def _base_result(path: Path, artifact: dict[str, Any], decode_as: list[str], display_filter: str | None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source": _source_reference(path, artifact),
        "status": "unknown",
        "parameters": {"decode_as": decode_as, "display_filter": display_filter},
        "tool": {"path": None, "version": None},
        "observations": [],
        "unknown_scopes": [],
        "artifacts": [],
        "metrics": {"observation_count": 0, "unknown_scope_count": 0},
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


def analyze_protocols(
    input_artifact: str | Path,
    output_dir: str | Path,
    *,
    tshark_path: str | Path | None = None,
    decode_as: Sequence[str] = (),
    display_filter: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    artifact_path = Path(input_artifact)
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    artifact = load_json_artifact(artifact_path)
    jsonschema.validate(artifact, json.loads(M01_SCHEMA.read_text(encoding="utf-8")))
    validate_m01_references(artifact)
    source = _resolve_source(artifact_path, artifact["path"])
    if not source.is_file():
        raise FileNotFoundError(f"M01 source does not exist: {source}")
    if sha256_file(source) != artifact["sha256"]:
        raise ValueError("M01 source SHA-256 mismatch")

    normalized_decode_as = list(decode_as)
    result = _base_result(artifact_path, artifact, normalized_decode_as, display_filter)
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

    run_options = {"capture_output": True, "text": True, "check": False}
    version_result = runner([str(executable), "-v"], **run_options)
    if version_result.returncode != 0:
        raise RuntimeError(f"tshark version check failed: {version_result.stderr.strip()}")
    result["tool"] = {"path": str(executable), "version": version_result.stdout.splitlines()[0].strip()}
    command = [str(executable), "-r", str(source), "-T", "json"]
    for field in ("frame.number", "frame.protocols", "tcp.stream", *[item for fields in PROTOCOL_FIELDS.values() for item in fields]):
        command.extend(["-e", field])
    for rule in normalized_decode_as:
        command.extend(["-d", rule])
    if display_filter:
        command.extend(["-Y", display_filter])
    completed = runner(command, **run_options)
    if completed.returncode != 0:
        raise RuntimeError(f"tshark protocol extraction failed: {completed.stderr.strip()}")
    try:
        packets = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("tshark returned invalid JSON") from exc
    if not isinstance(packets, list):
        raise RuntimeError("tshark returned invalid JSON packet root")

    packet_ids_by_frame = {item["index"] + 1: item["id"] for item in artifact["packets"]}
    observations: list[dict[str, Any]] = []
    for raw in packets:
        layers = raw.get("_source", {}).get("layers", {})
        try:
            frame_number = int(_first(layers, "frame.number"))
        except (TypeError, ValueError):
            raise RuntimeError("tshark packet missing valid frame.number")
        scope_id = packet_ids_by_frame.get(frame_number)
        if scope_id is None:
            raise RuntimeError(f"tshark frame {frame_number} has no M01 packet reference")
        hierarchy = str(_first(layers, "frame.protocols") or "").split(":")
        for protocol in sorted(set(hierarchy) & PROTOCOL_FIELDS.keys()):
            evidence = [
                {"field": field, "value": str(_first(layers, field))}
                for field in PROTOCOL_FIELDS[protocol]
                if _first(layers, field) is not None
            ]
            if not evidence:
                continue
            encrypted = protocol in ("tls", "ssh")
            observations.append({
                "observation_id": f"m07-{scope_id}-{protocol}",
                "scope_type": "packet", "scope_id": scope_id, "protocol": protocol,
                "recognition_mode": "decode_as" if normalized_decode_as else "dissector",
                "visibility": "metadata_only" if encrypted else "application_visible",
                "field_evidence": evidence,
                "limitations": ([f"{protocol.upper()} metadata does not establish recovered application plaintext without applicable decryption material."] if encrypted else []),
            })
    result["observations"] = sorted(observations, key=lambda item: item["observation_id"])
    if observations:
        result["status"] = "ok"
    else:
        result["status"] = "unknown"
        result["unknown_scopes"] = [{"scope_type": "input", "scope_id": artifact["id"], "reason_code": "NO_APPROVED_PROTOCOL_FIELDS"}]
    result["metrics"] = {"observation_count": len(observations), "unknown_scope_count": len(result["unknown_scopes"])}
    return _write_result(destination, result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record standard-protocol observations from an M01 capture artifact.")
    parser.add_argument("input_artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--decode-as", action="append", default=[])
    parser.add_argument("--display-filter")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_protocols(args.input_artifact, args.output_dir, tshark_path=args.tshark, decode_as=args.decode_as, display_filter=args.display_filter)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, jsonschema.ValidationError) as exc:
        print(f"m07: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "protocols.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

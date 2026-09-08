"""Shared artifact integrity and cross-reference validation helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    source = Path(path)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_artifact(
    path: str | Path, *, expected_sha256: str | None = None
) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"artifact does not exist: {source}")
    actual_sha256 = sha256_file(source)
    if expected_sha256 is not None and actual_sha256 != expected_sha256:
        raise ValueError(
            f"artifact SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"artifact is not valid UTF-8 JSON: {source}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"artifact root must be an object: {source}")
    return value


def validate_m01_references(artifact: dict[str, Any]) -> None:
    source_id = artifact.get("id")
    packets = artifact.get("packets", [])
    flows = artifact.get("flows", [])
    streams = artifact.get("streams", [])
    packet_ids = {item.get("id") for item in packets}
    flow_ids = {item.get("id") for item in flows}

    for collection_name, records in (
        ("packet", packets),
        ("flow", flows),
        ("stream", streams),
    ):
        for record in records:
            if record.get("source_id") != source_id:
                raise ValueError(
                    f"{collection_name} {record.get('id')!r} has mismatched source_id"
                )

    for record in [*flows, *streams]:
        for packet_id in record.get("packet_ids", []):
            if packet_id not in packet_ids:
                raise ValueError(
                    f"{record.get('id')!r} references unknown packet {packet_id!r}"
                )

    for stream in streams:
        if stream.get("flow_id") not in flow_ids:
            raise ValueError(
                f"stream {stream.get('id')!r} references unknown flow "
                f"{stream.get('flow_id')!r}"
            )
        directions = [item.get("direction") for item in stream.get("directions", [])]
        if len(directions) != len(set(directions)):
            raise ValueError(f"stream {stream.get('id')!r} repeats a direction")

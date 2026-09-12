#!/usr/bin/env python3
"""Derive the encrypted-network-traffic demo inputs from one committed capture.

The parent is a Wireshark 4.6.0 regression capture already registered in
``data/external/test-samples-manifest.json``; only the derived byte streams are
written here, with the parent hash and the transform recorded alongside.

    tls13-rfc8446.pcap  -> data/derived/tls13-app-ciphertext.dat
        The TLS 1.3 application_data (content type 0x17) record payloads of the
        first TCP stream, concatenated in capture order with the five-byte
        record headers removed. Nothing self-describing remains: this is the
        bytestream a passive observer holds once the record layer is peeled off.

    tls13-rfc8446.pcap  -> data/derived/tls13-record-stream.dat
        The same first TCP stream with its bytes untouched. The five-byte
        record headers are cleartext (content type, legacy version, two-byte
        big-endian length) per RFC 8446 section 5.1, so the record boundaries
        stay recoverable even though every payload is ciphertext.

Both artifacts come from the same parent, so the only difference between them
is the five cleartext header bytes per record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "external" / "raw" / "wireshark-v4.6.0"
OUT_DIR = ROOT / "data" / "derived"

TLS_PARENT = RAW / "tls13-rfc8446.pcap"

APP_DATA = 0x17


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _payloads_by_stream(tshark: Path, capture: Path) -> dict[int, bytes]:
    """Concatenate each TCP stream's payload, ordered by capture frame."""
    out = subprocess.run(
        [str(tshark), "-r", str(capture), "-T", "fields",
         "-e", "frame.number", "-e", "tcp.stream", "-e", "tcp.payload"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2]:
            continue
        rows.append((int(parts[0]), int(parts[1]), bytes.fromhex(parts[2].replace(":", ""))))
    rows.sort(key=lambda row: row[0])
    streams: dict[int, bytearray] = {}
    for _, stream, payload in rows:
        streams.setdefault(stream, bytearray()).extend(payload)
    return {key: bytes(value) for key, value in streams.items()}


def _tls_records(stream: bytes) -> list[tuple[int, int, int, int]]:
    """Walk the record layer: (start, end, content_type, declared_length)."""
    records: list[tuple[int, int, int, int]] = []
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        length = int.from_bytes(stream[offset + 3:offset + 5], "big")
        end = offset + 5 + length
        if end > len(stream):
            break
        records.append((offset, end, content_type, length))
        offset = end
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", type=Path,
                        default=Path(r"C:\Program Files\Wireshark\tshark.exe"))
    args = parser.parse_args(argv)
    tshark = args.tshark
    if not tshark.is_file():
        found = shutil.which("tshark")
        if not found:
            print(f"prepare-encrypted-case: tshark not found at {tshark}", file=sys.stderr)
            return 2
        tshark = Path(found)

    if not TLS_PARENT.is_file():
        print(f"prepare-encrypted-case: missing parent capture {TLS_PARENT}", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    tls_streams = _payloads_by_stream(tshark, TLS_PARENT)
    if not tls_streams:
        print("prepare-encrypted-case: no TCP payloads in the TLS capture", file=sys.stderr)
        return 2
    record_stream = tls_streams[min(tls_streams)]
    records = _tls_records(record_stream)
    application = [record for record in records if record[2] == APP_DATA]
    ciphertext = b"".join(record_stream[start + 5:end] for start, end, _, _ in application)
    if not ciphertext:
        print("prepare-encrypted-case: no application_data records found", file=sys.stderr)
        return 2

    ciphertext_path = OUT_DIR / "tls13-app-ciphertext.dat"
    record_path = OUT_DIR / "tls13-record-stream.dat"
    ciphertext_path.write_bytes(ciphertext)
    record_path.write_bytes(record_stream)

    manifest = {
        "schema_version": "0.1",
        "updated_at": "2026-09-12",
        "note": "Derived byte streams for the encrypted-network-traffic demonstration; "
                "regenerate with scripts/prepare_encrypted_network_case.py. Both artifacts "
                "share one parent, so the only difference is the five cleartext record "
                "header bytes per record.",
        "artifacts": [
            {
                "artifact_id": "derived-tls13-app-ciphertext",
                "path": "data/derived/tls13-app-ciphertext.dat",
                "parent_path": "data/external/raw/wireshark-v4.6.0/tls13-rfc8446.pcap",
                "parent_sha256": _sha256(TLS_PARENT),
                "transform": "TCP stream 0 payloads; TLS record headers (5 bytes) removed; "
                             f"{len(application)} application_data records concatenated",
                "byte_size": len(ciphertext),
                "sha256": _sha256(ciphertext_path),
            },
            {
                "artifact_id": "derived-tls13-record-stream",
                "path": "data/derived/tls13-record-stream.dat",
                "parent_path": "data/external/raw/wireshark-v4.6.0/tls13-rfc8446.pcap",
                "parent_sha256": _sha256(TLS_PARENT),
                "transform": "TCP stream 0 payloads concatenated in capture order, no bytes "
                             f"removed; {len(records)} TLS records, each preceded by a cleartext "
                             "5-byte header whose trailing two bytes are the big-endian length",
                "byte_size": len(record_stream),
                "sha256": _sha256(record_path),
            },
        ],
    }
    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"ciphertext    {ciphertext_path}  {len(ciphertext)} B  "
          f"({len(application)} application_data records)")
    print(f"record stream {record_path}  {len(record_stream)} B  ({len(records)} records, headers intact)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

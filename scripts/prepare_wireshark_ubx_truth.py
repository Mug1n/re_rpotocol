#!/usr/bin/env python3
"""Build a held-out UBX byte stream and independent Wireshark-derived truth.

The analysis pipeline never imports this module.  It receives only
``held_out.ubx.bin``.  This utility is the separate, post-analysis oracle: it
asks TShark's UBX dissector for message class/ID and payload length, then binds
the resulting labels to the exact byte stream with SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# ``subprocess`` builds a Windows command line itself.  The backslashes keep
# the CSV quotes intact when that command line is decoded by TShark.
DLT_UBX = 'uat:user_dlts:"User 1 (DLT=148)","ubx","0","","0",""'
SOURCE_URL = "https://gitlab.com/wireshark/wireshark/uploads/4f28724c211416eca9d4471aa205cafc/ubx_sample.pcap"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tshark_fields(tshark: Path, pcap: Path, fields: list[str], *, ubx: bool = False) -> list[list[str]]:
    command = [str(tshark)]
    if ubx:
        # On Windows, an argv list strips the embedded CSV quotes while it is
        # converted to a command line.  Supply the one UAT argument exactly as
        # documented by Wireshark instead.
        if os.name == "nt":
            quoted_fields = " ".join(f"-e {field}" for field in fields)
            raw_command = f'"{tshark}" -o "uat:user_dlts:\\"User 1 (DLT=148)\\",\\"ubx\\",\\"0\\",\\"\\",\\"0\\",\\"\\"" -Y ubx -r "{pcap}" -T fields {quoted_fields}'
            result = subprocess.run(raw_command, check=True, capture_output=True, text=True, encoding="utf-8")
            return [line.split("\t") for line in result.stdout.splitlines() if line]
        command.extend(["-o", DLT_UBX, "-Y", "ubx"])
    command.extend(["-r", str(pcap), "-T", "fields"])
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
    return [line.split("\t") for line in result.stdout.splitlines() if line]


def prepare(pcap: Path, tshark: Path, output: Path, holdout_modulus: int = 5) -> dict[str, Any]:
    if holdout_modulus < 2:
        raise ValueError("holdout modulus must be at least 2")
    if not pcap.is_file() or not tshark.is_file():
        raise FileNotFoundError("pcap or tshark executable does not exist")
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    raw_rows = tshark_fields(tshark, pcap, ["frame.number", "data.data"])
    decoded_rows = tshark_fields(tshark, pcap, ["frame.number", "ubx.msg_class_id", "ubx.payload_len"], ubx=True)
    raw_by_frame = {int(row[0]): bytes.fromhex(row[1]) for row in raw_rows if len(row) == 2 and row[1]}
    decoded = {int(row[0]): (row[1], int(row[2])) for row in decoded_rows if len(row) == 3 and row[1] and row[2]}
    common = sorted(set(raw_by_frame) & set(decoded))
    if len(common) < 3:
        raise ValueError("fewer than three frames were independently decoded as UBX")

    held_out_frames = [number for ordinal, number in enumerate(common, start=1) if ordinal % holdout_modulus == 0]
    discovery_frames = [number for number in common if number not in set(held_out_frames)]
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent))
    try:
        held_out = b"".join(raw_by_frame[number] for number in held_out_frames)
        discovery = b"".join(raw_by_frame[number] for number in discovery_frames)
        held_out_path = staging / "held_out.ubx.bin"
        discovery_path = staging / "discovery_only.ubx.bin"
        held_out_path.write_bytes(held_out)
        discovery_path.write_bytes(discovery)
        messages = []
        offset = 0
        for index, frame_number in enumerate(held_out_frames, start=1):
            raw = raw_by_frame[frame_number]
            class_id, payload_length = decoded[frame_number]
            if len(raw) != payload_length + 8:
                raise ValueError(f"frame {frame_number} does not match independent decoder length")
            end = offset + len(raw)
            messages.append({
                "id": f"ubx-heldout-{index:04d}", "start": offset, "end": end,
                "type": f"ubx-{class_id.lower()}",
                "fields": [
                    {"start": offset + 2, "end": offset + 4},
                    {"start": offset + 4, "end": offset + 6},
                    {"start": offset + 6, "end": end - 2},
                    {"start": end - 2, "end": end},
                ],
            })
            offset = end
        truth = {"schema_version": "0.1", "corpus_id": "wireshark-ubx-sample-heldout-v1", "input_sha256": sha256(held_out_path), "messages": messages}
        (staging / "held_out.truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        manifest = {
            "schema_version": "0.1", "corpus_id": truth["corpus_id"], "source_url": SOURCE_URL,
            "pcap_sha256": sha256(pcap), "tshark": str(tshark), "tshark_version": subprocess.run([str(tshark), "--version"], check=True, capture_output=True, text=True, encoding="utf-8").stdout.splitlines()[0],
            "truth_generator": "Wireshark UBX dissector via DLT_USER 148; generated separately from analysis",
            "selection": {"method": "capture-order modulo", "holdout_modulus": holdout_modulus, "held_out_frame_count": len(held_out_frames), "discovery_only_frame_count": len(discovery_frames)},
            "artifacts": {"held_out_input": held_out_path.name, "held_out_input_sha256": truth["input_sha256"], "truth": "held_out.truth.json", "discovery_only_input": discovery_path.name, "discovery_only_sha256": sha256(discovery_path)},
            "independence": {"analyzer_input": [held_out_path.name], "not_supplied_to_analyzer": ["held_out.truth.json", "discovery_only.ubx.bin", "UBX protocol specification", "Wireshark dissector output"]},
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(output)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a held-out UBX corpus with independent Wireshark truth.")
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--tshark", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--holdout-modulus", type=int, default=5)
    args = parser.parse_args()
    try:
        prepare(args.pcap, args.tshark, args.output_dir, args.holdout_modulus)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ubx-truth: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

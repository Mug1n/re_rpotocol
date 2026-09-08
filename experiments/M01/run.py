#!/usr/bin/env python3
"""M1 DAT-first input triage and capture extraction CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"): ("<", "microseconds"),
    bytes.fromhex("4d3cb2a1"): ("<", "nanoseconds"),
    bytes.fromhex("a1b2c3d4"): (">", "microseconds"),
    bytes.fromhex("a1b23c4d"): (">", "nanoseconds"),
}
PCAPNG_BLOCK_TYPE = bytes.fromhex("0a0d0d0a")
PCAPNG_BOMS = {
    bytes.fromhex("4d3c2b1a"): "<",
    bytes.fromhex("1a2b3c4d"): ">",
}
WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
WINDOWS_CAPINFOS = Path(r"C:\Program Files\Wireshark\capinfos.exe")
HEX_LINE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class ProbeResult:
    format: str
    rule_id: str
    observation: str
    warnings: tuple[str, ...] = ()

    def evidence(self) -> list[dict[str, str]]:
        return [{"rule_id": self.rule_id, "observation": self.observation}]


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _copy_with_sha256(source: Path, destination: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as reader, destination.open("wb") as writer:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            writer.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def _safe_id(path: Path, sha256: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip("-") or "input"
    return f"{stem}-{sha256[:12]}"


def _find_tool(
    explicit: str | Path | None,
    name: str,
    windows_default: Path,
) -> Path:
    if explicit is not None:
        candidate = Path(explicit)
        if candidate.is_file():
            return candidate
        raise FileNotFoundError(f"{name} not found at {candidate}")
    discovered = shutil.which(name)
    if discovered:
        return Path(discovered)
    wireshark_home = os.environ.get("WIRESHARK_HOME")
    if wireshark_home:
        bundled = Path(wireshark_home) / f"{name}.exe"
        if bundled.is_file():
            return bundled
    if windows_default.is_file():
        return windows_default
    raise FileNotFoundError(
        f"{name} is required for capture input; pass --{name.replace('_', '-')} PATH"
    )


def _run_tool(args: Iterable[str | Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(item) for item in args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _capinfos_reports(
    path: Path,
    expected: str,
    capinfos_path: str | Path | None,
) -> tuple[bool, str]:
    tool = _find_tool(capinfos_path, "capinfos", WINDOWS_CAPINFOS)
    completed = _run_tool([tool, "-t", path])
    output = f"{completed.stdout}\n{completed.stderr}".strip()
    if completed.returncode != 0:
        return False, f"capinfos exit={completed.returncode}: {output}"
    lowered = output.lower()
    if expected == "pcapng":
        matched = "pcapng" in lowered
    else:
        matched = "pcap" in lowered and "pcapng" not in lowered
    return matched, output


def _validate_pcap(path: Path, endian: str) -> tuple[bool, str]:
    size = path.stat().st_size
    if size < 24:
        return False, "global header truncated"
    with path.open("rb") as stream:
        header = stream.read(24)
        major, minor = struct.unpack(f"{endian}HH", header[4:8])
        if (major, minor) != (2, 4):
            return False, f"unsupported header version {major}.{minor}"
        snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
        offset = 24
        while offset < size:
            packet_header = stream.read(16)
            if len(packet_header) != 16:
                return False, f"packet header truncated at offset {offset}"
            captured_length, original_length = struct.unpack(
                f"{endian}II", packet_header[8:16]
            )
            if captured_length > snaplen and snaplen:
                return False, (
                    f"captured length {captured_length} exceeds snaplen {snaplen} "
                    f"at offset {offset}"
                )
            if captured_length > original_length:
                return False, (
                    f"captured length {captured_length} exceeds original length "
                    f"{original_length} at offset {offset}"
                )
            payload = stream.read(captured_length)
            if len(payload) != captured_length:
                return False, f"packet data truncated at offset {offset + 16}"
            offset += 16 + captured_length
    return True, "complete PCAP global header and record structure"


def _validate_pcapng(path: Path) -> tuple[bool, str]:
    size = path.stat().st_size
    if size < 28:
        return False, "section header truncated"
    offset = 0
    endian: str | None = None
    sections = 0
    with path.open("rb") as stream:
        while offset < size:
            stream.seek(offset)
            prefix = stream.read(12)
            if len(prefix) < 12:
                return False, f"block header truncated at offset {offset}"
            if prefix[:4] == PCAPNG_BLOCK_TYPE:
                endian = PCAPNG_BOMS.get(prefix[8:12])
                if endian is None:
                    return False, f"invalid byte-order magic at offset {offset + 8}"
                sections += 1
            elif endian is None:
                return False, "first block is not a Section Header Block"
            total_length = struct.unpack(f"{endian}I", prefix[4:8])[0]
            minimum = 28 if prefix[:4] == PCAPNG_BLOCK_TYPE else 12
            if total_length < minimum:
                return False, f"block length {total_length} below minimum at {offset}"
            if total_length % 4:
                return False, f"block length {total_length} is not 4-byte aligned"
            if offset + total_length > size:
                return False, f"block at offset {offset} extends past end of file"
            stream.seek(offset + total_length - 4)
            trailer = stream.read(4)
            if len(trailer) != 4:
                return False, f"block trailer truncated at offset {offset}"
            trailer_length = struct.unpack(f"{endian}I", trailer)[0]
            if trailer_length != total_length:
                return False, f"block length trailer mismatch at offset {offset}"
            offset += total_length
    if offset != size:
        return False, f"unparsed trailing bytes begin at offset {offset}"
    if sections == 0:
        return False, "no Section Header Block"
    return True, f"validated {sections} pcapng section(s) and all block lengths"


def probe_format(
    path: str | Path,
    *,
    capinfos_path: str | Path | None = None,
) -> ProbeResult:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"input does not exist: {source}")
    if not source.is_file():
        raise ValueError(f"input is not a regular file: {source}")
    size = source.stat().st_size
    if size == 0:
        return ProbeResult(
            "raw_bytes",
            "M01-FMT-EMPTY",
            "Input is zero-length; external format heuristics are not accepted.",
            ("Input contains no bytes.",),
        )
    with source.open("rb") as stream:
        prefix = stream.read(12)
    magic = prefix[:4]
    if magic == PCAPNG_BLOCK_TYPE:
        valid, detail = _validate_pcapng(source)
        if not valid:
            rule = (
                "M01-FMT-PCAPNG-HEADER-TRUNCATED"
                if size < 28
                else "M01-FMT-PCAPNG-STRUCTURE-INVALID"
            )
            return ProbeResult(
                "raw_bytes",
                rule,
                f"PCAPNG-like signature rejected: {detail}.",
                ("Capture-like prefix was preserved as raw bytes after validation failed.",),
            )
        reported, report = _capinfos_reports(source, "pcapng", capinfos_path)
        if not reported:
            return ProbeResult(
                "raw_bytes",
                "M01-FMT-PCAPNG-TOOL-MISMATCH",
                f"PCAPNG structure passed but capinfos did not report PCAPNG: {report}",
                ("Conflicting format evidence; input preserved as raw bytes.",),
            )
        return ProbeResult(
            "pcapng",
            "M01-FMT-PCAPNG-VALIDATED",
            f"{detail}; capinfos reports PCAPNG.",
        )
    if magic in PCAP_MAGICS:
        endian, precision = PCAP_MAGICS[magic]
        valid, detail = _validate_pcap(source, endian)
        if not valid:
            rule = (
                "M01-FMT-PCAP-GLOBAL-HEADER-TRUNCATED"
                if size < 24
                else "M01-FMT-PCAP-STRUCTURE-INVALID"
            )
            return ProbeResult(
                "raw_bytes",
                rule,
                f"PCAP-like signature rejected: {detail}.",
                ("Capture-like prefix was preserved as raw bytes after validation failed.",),
            )
        reported, report = _capinfos_reports(source, "pcap", capinfos_path)
        if not reported:
            return ProbeResult(
                "raw_bytes",
                "M01-FMT-PCAP-TOOL-MISMATCH",
                f"PCAP structure passed but capinfos did not report PCAP: {report}",
                ("Conflicting format evidence; input preserved as raw bytes.",),
            )
        return ProbeResult(
            "pcap",
            "M01-FMT-PCAP-VALIDATED",
            f"{detail}; timestamp precision={precision}; capinfos reports PCAP.",
        )
    return ProbeResult(
        "raw_bytes",
        "M01-FMT-NO-KNOWN-MAGIC",
        "No validated capture/container signature; filename suffix was not used as proof.",
        ("File extension does not define the internal format.",),
    )


def _first(layers: dict[str, Any], name: str) -> str | None:
    value = layers.get(name)
    if isinstance(value, list):
        return str(value[0]) if value else None
    if value is None:
        return None
    return str(value)


def _to_int(value: str | None) -> int | None:
    return int(value) if value not in (None, "") else None


def _present(layers: dict[str, Any], name: str) -> bool:
    return name in layers


def _decode_hex(value: str | None) -> bytes:
    if not value:
        return b""
    normalized = value.replace(":", "").replace(" ", "")
    return bytes.fromhex(normalized)


def _extract_packets(
    source: Path,
    input_id: str,
    output_dir: Path,
    tshark: Path,
) -> list[dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.interface_id",
        "frame.file_off",
        "frame.cap_len",
        "frame.len",
        "tcp.stream",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "ip.dst",
        "ipv6.dst",
        "tcp.dstport",
        "tcp.seq_raw",
        "tcp.len",
        "tcp.payload",
        "tcp.analysis.retransmission",
        "tcp.analysis.out_of_order",
        "tcp.analysis.lost_segment",
    ]
    args: list[str | Path] = [tshark, "-r", source, "-T", "json"]
    for field in fields:
        args.extend(["-e", field])
    completed = _run_tool(args)
    if completed.returncode != 0:
        raise RuntimeError(
            f"tshark packet extraction failed with exit {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    try:
        raw_packets = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"tshark returned invalid JSON: {exc}") from exc
    payload_dir = output_dir / "payloads"
    payload_dir_ready = False
    packets: list[dict[str, Any]] = []
    for raw in raw_packets:
        layers = raw.get("_source", {}).get("layers", {})
        frame_number = _to_int(_first(layers, "frame.number"))
        if frame_number is None:
            raise RuntimeError("tshark packet missing frame.number")
        payload = _decode_hex(_first(layers, "tcp.payload"))
        payload_ref: str | None = None
        if payload:
            if not payload_dir_ready:
                payload_dir.mkdir(parents=True, exist_ok=True)
                payload_dir_ready = True
            payload_path = payload_dir / f"{input_id}-packet-{frame_number:06d}.bin"
            payload_path.write_bytes(payload)
            payload_ref = payload_path.relative_to(output_dir).as_posix()
        captured_length = _to_int(_first(layers, "frame.cap_len"))
        original_length = _to_int(_first(layers, "frame.len"))
        source_offset = _to_int(_first(layers, "frame.file_off"))
        packets.append(
            {
                "id": f"{input_id}-packet-{frame_number}",
                "source_id": input_id,
                "index": frame_number - 1,
                "timestamp_epoch": _first(layers, "frame.time_epoch"),
                "interface_id": _to_int(_first(layers, "frame.interface_id")),
                "captured_length": captured_length,
                "original_length": original_length,
                "truncated": (
                    captured_length is not None
                    and original_length is not None
                    and captured_length < original_length
                ),
                "source_file_offset": source_offset,
                "source_offset_reason": (
                    None
                    if source_offset is not None
                    else "frame.file_off was not populated by tshark"
                ),
                "tcp_stream": _to_int(_first(layers, "tcp.stream")),
                "src_ip": _first(layers, "ip.src") or _first(layers, "ipv6.src"),
                "src_port": _to_int(_first(layers, "tcp.srcport")),
                "dst_ip": _first(layers, "ip.dst") or _first(layers, "ipv6.dst"),
                "dst_port": _to_int(_first(layers, "tcp.dstport")),
                "tcp_seq_raw": _to_int(_first(layers, "tcp.seq_raw")),
                "tcp_payload_length": _to_int(_first(layers, "tcp.len")),
                "payload_ref": payload_ref,
                "analysis": {
                    "retransmission": _present(
                        layers, "tcp.analysis.retransmission"
                    ),
                    "out_of_order": _present(layers, "tcp.analysis.out_of_order"),
                    "gap_or_loss": _present(
                        layers, "tcp.analysis.lost_segment"
                    ),
                },
            }
        )
    return packets


def _follow_stream(
    source: Path,
    stream_id: int,
    tshark: Path,
) -> tuple[bytes, bytes]:
    completed = _run_tool(
        [tshark, "-r", source, "-q", "-z", f"follow,tcp,raw,{stream_id}"]
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"tshark stream {stream_id} follow failed with exit "
            f"{completed.returncode}: {completed.stderr.strip()}"
        )
    node0 = bytearray()
    node1 = bytearray()
    for line in completed.stdout.splitlines():
        token = line.strip()
        if not token or not HEX_LINE.fullmatch(token) or len(token) % 2:
            continue
        target = node1 if line.startswith("\t") else node0
        target.extend(bytes.fromhex(token))
    return bytes(node0), bytes(node1)


def _build_tcp_objects(
    source: Path,
    input_id: str,
    output_dir: Path,
    tshark: Path,
    packets: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for packet in packets:
        stream_id = packet["tcp_stream"]
        if stream_id is not None:
            grouped.setdefault(stream_id, []).append(packet)
    flows: list[dict[str, Any]] = []
    streams: list[dict[str, Any]] = []
    stream_dir = output_dir / "streams"
    stream_dir_ready = False
    for stream_id, members in sorted(grouped.items()):
        first = members[0]
        node0 = {
            "ip": first["src_ip"],
            "port": first["src_port"],
        }
        node1 = {
            "ip": first["dst_ip"],
            "port": first["dst_port"],
        }
        direction0, direction1 = _follow_stream(source, stream_id, tshark)
        direction_items: list[dict[str, Any]] = []
        for direction, payload in (
            ("node0_to_node1", direction0),
            ("node1_to_node0", direction1),
        ):
            if not payload:
                continue
            if not stream_dir_ready:
                stream_dir.mkdir(parents=True, exist_ok=True)
                stream_dir_ready = True
            payload_path = stream_dir / f"{input_id}-tcp-{stream_id}-{direction}.bin"
            payload_path.write_bytes(payload)
            direction_items.append(
                {
                    "direction": direction,
                    "length": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "artifact_ref": payload_path.relative_to(output_dir).as_posix(),
                }
            )
        analysis = {
            "retransmission_packets": sum(
                1 for packet in members if packet["analysis"]["retransmission"]
            ),
            "out_of_order_packets": sum(
                1 for packet in members if packet["analysis"]["out_of_order"]
            ),
            "gap_or_loss_packets": sum(
                1 for packet in members if packet["analysis"]["gap_or_loss"]
            ),
            "truncated_packets": sum(1 for packet in members if packet["truncated"]),
        }
        packet_ids = [packet["id"] for packet in members]
        flow_id = f"{input_id}-tcp-flow-{stream_id}"
        flows.append(
            {
                "id": flow_id,
                "source_id": input_id,
                "transport": "tcp",
                "tcp_stream": stream_id,
                "node0": node0,
                "node1": node1,
                "packet_ids": packet_ids,
                "first_timestamp_epoch": members[0]["timestamp_epoch"],
                "last_timestamp_epoch": members[-1]["timestamp_epoch"],
            }
        )
        streams.append(
            {
                "id": f"{input_id}-tcp-stream-{stream_id}",
                "source_id": input_id,
                "flow_id": flow_id,
                "tcp_stream": stream_id,
                "node0": node0,
                "node1": node1,
                "packet_ids": packet_ids,
                "directions": direction_items,
                "analysis": analysis,
                "reassembly_status": (
                    "partial" if analysis["truncated_packets"] else "complete"
                ),
            }
        )
    return flows, streams


def _analyze_into(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    tshark_path: str | Path | None = None,
    capinfos_path: str | Path | None = None,
) -> dict[str, Any]:
    source = Path(input_path)
    destination = Path(output_dir)
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError(f"output directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)

    probe = probe_format(source, capinfos_path=capinfos_path)
    size = source.stat().st_size
    raw_copy: Path | None = None
    if probe.format == "raw_bytes" and size:
        payload_dir = destination / "payloads"
        payload_dir.mkdir(parents=True, exist_ok=True)
        raw_copy = payload_dir / ".raw-input.tmp"
        digest = _copy_with_sha256(source, raw_copy)
    else:
        digest = _sha256(source)
    input_id = _safe_id(source, digest)
    result: dict[str, Any] = {
        "schema_version": "0.1",
        "id": input_id,
        "path": str(source),
        "sha256": digest,
        "length": size,
        "format": probe.format,
        "format_evidence": probe.evidence(),
        "metadata_availability": {
            "packet_boundaries": False,
            "network_headers": False,
            "flow_identity": False,
            "direction": False,
            "timestamps": False,
        },
        "status": "empty" if size == 0 else "ok",
        "byte_ranges": [],
        "packets": [],
        "flows": [],
        "streams": [],
        "warnings": list(probe.warnings),
    }
    if probe.format == "raw_bytes":
        if size:
            payload_path = payload_dir / f"{input_id}.bin"
            if raw_copy is None:
                raise RuntimeError("raw input staging artifact was not created")
            raw_copy.replace(payload_path)
            result["byte_ranges"] = [
                {
                    "start": 0,
                    "end": size,
                    "artifact_ref": payload_path.relative_to(destination).as_posix(),
                }
            ]
    else:
        tshark = _find_tool(tshark_path, "tshark", WINDOWS_TSHARK)
        packets = _extract_packets(source, input_id, destination, tshark)
        flows, streams = _build_tcp_objects(
            source, input_id, destination, tshark, packets
        )
        result["metadata_availability"] = {
            "packet_boundaries": True,
            "network_headers": True,
            "flow_identity": True if flows else "partial",
            "direction": True if flows else "partial",
            "timestamps": True,
        }
        result["byte_ranges"] = [
            {
                "start": 0,
                "end": size,
                "artifact_ref": str(source),
            }
        ]
        result["packets"] = packets
        result["flows"] = flows
        result["streams"] = streams
        if any(packet["truncated"] for packet in packets):
            result["status"] = "partial"
            result["warnings"].append(
                "One or more captured packets are shorter than their original length."
            )
        if any(packet["source_file_offset"] is None for packet in packets):
            result["warnings"].append(
                "TShark did not populate frame.file_off; packet source offsets are null."
            )
    result_path = destination / "result.json"
    result_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def analyze_input(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    tshark_path: str | Path | None = None,
    capinfos_path: str | Path | None = None,
) -> dict[str, Any]:
    """Analyze into a staging directory, then publish the result atomically."""
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.tmp-",
            dir=destination.parent,
        )
    )
    try:
        result = _analyze_into(
            input_path,
            staging,
            tshark_path=tshark_path,
            capinfos_path=capinfos_path,
        )
        staging.replace(destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Classify .dat by validated content, preserve raw bytes, and extract "
            "packet/flow/stream evidence from confirmed PCAP or PCAPNG."
        )
    )
    parser.add_argument("input", type=Path, help="Input .dat/.bin/.pcap/.pcapng")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory for result.json and binary artifacts",
    )
    parser.add_argument("--tshark", type=Path, help="Explicit tshark executable")
    parser.add_argument("--capinfos", type=Path, help="Explicit capinfos executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        analyze_input(
            args.input,
            args.output_dir,
            tshark_path=args.tshark,
            capinfos_path=args.capinfos,
        )
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as exc:
        print(f"m01: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


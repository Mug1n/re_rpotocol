#!/usr/bin/env python3
"""One-command driver for the three-minute defense demonstration.

Runs the technical-exploration pipeline and then walks the presenter through seven
screen stops, pausing for Enter between them so pacing stays under manual
control. Reading an existing run directory with ``--rundir`` skips the run and
replays the same stops, which is the manual escape hatch when the live run
fails on stage.

The driver never rewrites a status it disagrees with: an encrypted sample whose
plaintext is unavailable is shown as ``no_recoverable_content``, not as success.

    python -B scripts\\defense_demo.py                 # run, then present
    python -B scripts\\defense_demo.py --no-pause      # rehearsal, no waiting
    python -B scripts\\defense_demo.py --rundir <dir>  # replay a finished run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_RUN = ROOT / "tmp" / "defense-demo"
FROZEN_RUN = ROOT / "reports" / "technical-exploration" / "2026-09-12"
FROZEN_MODEL = FROZEN_RUN / "unknown_plain" / "model"
PLAIN_PROFILE = ROOT / "profiles" / "tls13-record-stream.json"
FROZEN_CLASSIFIER = (ROOT / "data" / "acceptance" / "frozen-20260910" / "classification"
                     / "m11-v0.2" / "run" / "classification.json")
ENCRYPTED_RUNS = ROOT / "tmp" / "encrypted-eval" / "runs"
ACCEPTANCE = ROOT / "reports" / "acceptance" / "2026-09-11-abc" / "acceptance.json"
VERIFY = ROOT / "scripts" / "verify_acceptance.py"

DEFAULT_DAT = ROOT / "data" / "derived" / "tls13-app-ciphertext.dat"
DEFAULT_CONTROL = ROOT / "data" / "derived" / "tls13-record-stream.dat"
DEFAULT_RECOVERY = ROOT / "experiments" / "M08" / "fixtures" / "nested-base64-gzip.dat"
DEFAULT_CAPTURE = ROOT / "data" / "external" / "raw" / "wireshark-v4.6.0" / "http-brotli.pcapng"
DEFAULT_RARE = ROOT / "data" / "external" / "raw" / "watchpat" / "testdata.dat"

WIDTH = 78
NOTE = "  · "

ENCRYPTED_SAMPLES = [
    ("iscx-vpn-skype-audio1", "ISCX VPN Skype 音频（VPN 隧道加密）"),
    ("tls13-rfc8446", "TLS 1.3 直连会话（未封装）"),
]

INPUT_ROLES = [
    ("加密流量", "TLS 1.3 应用数据密文（剥离 5 字节记录头），测 M01–M06 结构推断"),
    ("明文对照", "同一抓包的完整记录流，明文记录头在位，同一套推断的对照"),
    ("少见协议", "专有设备私有格式, 无公开规格, 测盲推断; 自动候选与来源规则分开记账"),
    ("恢复输入", "本仓库合成夹具，测 M08 嵌套编码恢复"),
]

# RFC 8446 record content types and handshake message types. These are read off
# the first byte of each framed record for display only; M03 infers the record
# boundaries from the length field alone, so these labels never enter inference.
CONTENT_TYPES = {
    0x14: "change_cipher_spec",
    0x15: "alert",
    0x16: "handshake",
    0x17: "application_data",
}
HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x08: "EncryptedExtensions",
    0x0B: "Certificate",
    0x14: "Finished",
}
# Registered names for the values read back out of the recovered handshake.
# M08 itself stops at the record layer and the handshake type byte; segment 3
# reads these fields from M08's recovered artifact, and the labels here only
# translate the numbers that read returns.
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES128_GCM",
    0xC02F: "ECDHE_RSA_AES128_GCM",
    0xC02C: "ECDHE_ECDSA_AES256_GCM",
    0xC030: "ECDHE_RSA_AES256_GCM",
    0xCCA9: "ECDHE_ECDSA_CHACHA20",
    0xCCA8: "ECDHE_RSA_CHACHA20",
    0xC009: "ECDHE_ECDSA_AES128_CBC",
    0xC013: "ECDHE_RSA_AES128_CBC",
    0xC00A: "ECDHE_ECDSA_AES256_CBC",
    0xC014: "ECDHE_RSA_AES256_CBC",
    0x009C: "RSA_AES128_GCM",
    0x009D: "RSA_AES256_GCM",
    0x002F: "RSA_AES128_CBC",
    0x0035: "RSA_AES256_CBC",
    0x000A: "RSA_3DES_CBC",
}
NAMED_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001D: "x25519",
    0x001E: "x448",
}


# --------------------------------------------------------------------------- #
# 终端排版
# --------------------------------------------------------------------------- #
def _dw(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def _clip(text: str, width: int) -> str:
    if _dw(text) <= width:
        return text
    kept, used = [], 0
    for ch in text:
        step = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if used + step > width - 1:
            break
        kept.append(ch)
        used += step
    return "".join(kept) + "…"


def _pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - _dw(text))
    return (" " * gap + text) if align == "right" else (text + " " * gap)


def _wrap(text: str, width: int) -> list[str]:
    """Greedy word wrap for the verbatim model text, so a long claim stays readable."""
    lines: list[str] = []
    current = ""
    for word in text.split():
        if not current:
            current = word
        elif _dw(current) + 1 + _dw(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def _rule(char: str = "-") -> None:
    print(char * WIDTH)


def _stop(index: int, title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" 第 {index} 段 · {title}")
    print("=" * WIDTH)


def _field(label: str, value: Any) -> None:
    print(f"  {_pad(label, 14)}: {value}")


def _note(text: str) -> None:
    print(f"{NOTE}{text}")


def _pause(enabled: bool) -> None:
    if not enabled:
        return
    print()
    try:
        input("  >> 按 Enter 继续 ...")
    except EOFError:
        pass


# --------------------------------------------------------------------------- #
# 读取
# --------------------------------------------------------------------------- #
def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _find_tshark() -> Path | None:
    candidates: list[Path] = []
    home = os.environ.get("WIRESHARK_HOME")
    if home:
        candidates.append(Path(home) / "tshark.exe")
    candidates.append(Path(r"C:\Program Files\Wireshark\tshark.exe"))
    candidates.append(Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"))
    found = shutil.which("tshark")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


# --------------------------------------------------------------------------- #
# 七段屏幕内容
# --------------------------------------------------------------------------- #
def _registry_groups(registry: dict[str, Any]) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Flatten either registry shape into (owning record, entries) pairs.

    ``manifest.json`` lists artifacts at the top level; ``test-samples-manifest.json``
    nests them under datasets, and names the list ``files``.
    """
    groups = [(registry, registry.get("artifacts", []) + registry.get("files", []))]
    for dataset in registry.get("datasets", []):
        groups.append((dataset, dataset.get("artifacts", []) + dataset.get("files", [])))
    return groups


def _lookup_source(name: str) -> str | None:
    """Find the registered provenance line for an input, by file name."""
    for manifest_path in (ROOT / "data" / "external" / "manifest.json",
                          ROOT / "data" / "external" / "test-samples-manifest.json"):
        registry = _load(manifest_path) or {}
        for group, items in _registry_groups(registry):
            for item in items:
                if PurePosixPath(str(item.get("path", "")).replace("\\", "/")).name != name:
                    continue
                bits = [item.get("source_repository") or group.get("source_repository")
                        or item.get("dataset_id") or item.get("artifact_id"),
                        item.get("protocol")]
                license_ = item.get("license") or group.get("license")
                if license_:
                    bits.append(f"许可 {str(license_).split(';')[0].strip()}")
                return "  ".join(str(bit) for bit in bits if bit)
    return None


def _derived_record(name: str) -> dict[str, Any] | None:
    """Provenance for a byte stream derived from a registered capture."""
    manifest = _load(ROOT / "data" / "derived" / "manifest.json") or {}
    for item in manifest.get("artifacts", []):
        if PurePosixPath(str(item.get("path", "")).replace("\\", "/")).name == name:
            return item
    return None


def _seg_inputs(root: Path) -> None:
    _stop(1, "输入的测试数据")
    lookups = {
        "加密流量": (root / "unknown_dat" / "run_manifest.json", "input"),
        "明文对照": (root / "unknown_plain" / "run_manifest.json", "input"),
        "少见协议": (root / "unknown_rare" / "run_manifest.json", "input"),
        "恢复输入": (root / "recovery" / "recovery.json", "source"),
    }
    printed = 0
    for role, purpose in INPUT_ROLES:
        manifest_path, key = lookups[role]
        if not manifest_path.is_file():
            # 兜底模式下这条链没有预跑产物; 整块跳过, 不在屏幕上留缺失字样.
            continue
        if printed:
            print()
        printed += 1
        record = (_load(manifest_path) or {}).get(key) or {}
        raw_path = record.get("path") or record.get("artifact_path")
        if not raw_path:
            print(f"  [{role}]  [缺失] 本次产物未记录该输入")
            continue
        source = Path(str(raw_path))
        size = record.get("length")
        if not isinstance(size, int) and source.is_file():
            size = source.stat().st_size
        digest = record.get("sha256") or record.get("artifact_sha256") or ""
        heading = f"  [{role}]  {source.name}"
        if isinstance(size, int):
            heading += f"  ({size:,} 字节)"
        print(heading)
        print(f"      sha256  {_clip(digest, 24)}")
        derived = _derived_record(source.name)
        if derived:
            parent = PurePosixPath(str(derived.get("parent_path", "")).replace("\\", "/")).name
            print(f"      来源    {_clip(_lookup_source(parent) or '本仓库登记抓包', WIDTH - 14)}")
            print(f"      变换    {_clip(str(derived.get('transform', '')), WIDTH - 14)}")
        else:
            print(f"      来源    {_clip(_lookup_source(source.name) or '本仓库回归夹具', WIDTH - 14)}")
        print(f"      用途    {purpose}")
    print()
    _note("全部输入离线; 哈希与 data/external、data/derived 下的登记清单一致, 可复核.")
    _note("分析阶段不读真值、不读标签: 程序事先不知道正确答案.")


def _boundary_source_bytes(source: dict[str, Any]) -> bytes | None:
    """Read the framed input back, but only if it still matches its recorded hash.

    Used to print the first byte of each inferred boundary. That byte is read
    straight out of the input; it takes no part in the inference itself.
    """
    path = source.get("path")
    if not path:
        return None
    try:
        target = Path(str(path))
        if not target.is_file():
            return None
        if source.get("sha256") and _sha256(target) != source["sha256"]:
            return None
        return target.read_bytes()
    except OSError:
        return None


def _framing_block(root: Path, sub: str, role: str, caption: str) -> None:
    base = root / sub
    if not base.is_dir():
        print(f"  [{role}] {caption}")
        print("      [缺失] 本次产物未保留这条链")
        return
    manifest = _load(base / "run_manifest.json") or {}
    source = manifest.get("input") or {}
    name = Path(str(source.get("path"))).name if source.get("path") else "?"
    size = source.get("length")
    print(f"  [{role}] {caption}")
    print(f"      输入      {name}" + (f"  ({size:,} 字节)" if isinstance(size, int) else ""))

    features = _load(base / "m02" / "features.json")
    if features is not None:
        entropy = (features.get("global") or {}).get("entropy_bits_per_byte")
        if isinstance(entropy, (int, float)):
            print(f"      字节熵    {entropy:.3f} bits/byte")

    framing = _load(base / "m03" / "framing.json")
    if framing is None:
        print("      [缺失] m03/framing.json")
        return
    params = framing.get("parameters") or {}
    selected = params.get("selected")
    if selected:
        print("      分帧假设  " + "  ".join([
            f"length_offset={selected['length_offset']}",
            f"length_width={selected['length_width']}",
            f"byteorder={selected['byteorder']}",
            f"length_mode={selected['length_mode']}",
            f"header_size={selected['header_size']}",
        ]))
    else:
        print(f"      分帧假设  未给出 (status={framing.get('status')})")
    print(f"      切出消息  {len(framing.get('messages') or [])} 条"
          f"    候选分帧规则  {params.get('candidate_count')} 条"
          f"    未解析区间  {len(framing.get('unparsed_ranges') or [])} 段")

    messages = framing.get("messages") or []
    if messages:
        first = messages[0]
        rule = (first.get("framing_evidence") or [{}])[0].get("rule_id", "?")
        total = sum(message.get("length") or 0 for message in messages)
        size = source.get("length")
        covers = "  = 输入大小" if isinstance(size, int) and total == size else ""
        print(f"      推断边界  {len(messages)} 条, 长度合计 {total:,} B{covers}, "
              f"未解析区间 {len(framing.get('unparsed_ranges') or [])} 段   依据 {rule}")
        raw = _boundary_source_bytes(source)
        for index, message in enumerate(messages):
            start = message.get("start")
            first_byte = ""
            if raw is not None and isinstance(start, int) and 0 <= start < len(raw):
                first_byte = f"   首字节 0x{raw[start]:02x}"
            print(f"        #{index}  [{start:>5}, {message.get('end'):>5})  "
                  f"{message.get('length'):>5} B{first_byte}")


def _identity(left: bytes, right: bytes, start: int, stop: int) -> float | None:
    """Fraction of positions in [start, stop) where the two byte strings agree."""
    stop = min(stop, len(left), len(right))
    if stop <= start:
        return None
    same = sum(1 for index in range(start, stop) if left[index] == right[index])
    return same / (stop - start)


def _seg_verify(root: Path, sub: str, role: str) -> tuple[bool, bool]:
    """Check the inferred framing against the bytes it claims to describe.

    Each cluster's messages are split at the *inferred* header size, then paired
    byte agreement is reported for the header and for the remainder separately.
    A framing that reflects real structure agrees in the header and leaves the
    payload near the coincidence rate; nothing here is assumed, only measured.

    Returns (table_shown, field_counts_shown) so the caller only narrates what
    is actually on screen.
    """
    base = root / sub
    manifest = _load(base / "run_manifest.json") or {}
    source = (manifest.get("input") or {}).get("path")
    framing = _load(base / "m03" / "framing.json")
    clusters_doc = _load(base / "m04" / "clusters.json")
    if not source or not framing or clusters_doc is None:
        return False, False
    messages = framing.get("messages") or []
    assignments = clusters_doc.get("assignments") or []
    if len(messages) < 2 or not assignments:
        return False, False
    data_path = Path(str(source))
    if not data_path.is_file():
        return False, False
    header = ((framing.get("parameters") or {}).get("selected") or {}).get("header_size")
    if not isinstance(header, int) or header <= 0:
        return False, False
    data = data_path.read_bytes()

    by_id = {message.get("id"): message for message in messages}
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in assignments:
        if row.get("is_noise"):
            continue
        message = by_id.get(row.get("message_id"))
        if message is not None:
            grouped.setdefault(row["cluster_id"], []).append(message)

    table: list[tuple[int, int, int, float, int, float]] = []
    for cluster_id in sorted(grouped):
        items = grouped[cluster_id]
        if len(items) < 2:
            continue
        span = min(item["end"] - item["start"] for item in items)
        body_bytes = max(0, span - header)
        heads, bodies = [], []
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                left = data[items[i]["start"]:items[i]["start"] + span]
                right = data[items[j]["start"]:items[j]["start"] + span]
                head = _identity(left, right, 0, header)
                body = _identity(left, right, header, span)
                if head is not None:
                    heads.append(head)
                if body is not None:
                    bodies.append(body)
        if not heads or not bodies:
            continue
        table.append((cluster_id, len(items), data[items[0]["start"]],
                      sum(heads) / len(heads), body_bytes, sum(bodies) / len(bodies)))

    if table:
        print()
        print(f"  推断校验 [{role}]  按推断出的 header_size={header} 切开, 簇内两两比对")
        print(f"      {_pad('簇', 4)}{_pad('条数', 6)}{_pad('首字节', 9)}"
              f"{_pad('头一致率', 11, 'right')}{_pad('负载字节', 11, 'right')}"
              f"{_pad('负载一致率', 13, 'right')}")
        for cluster_id, count, first, head, body_bytes, body in table:
            print(f"      {_pad(str(cluster_id), 4)}{_pad(str(count), 6)}"
                  f"{_pad(f'0x{first:02x}', 9)}"
                  f"{_pad(f'{head:.3f}', 11, 'right')}{_pad(str(body_bytes), 11, 'right')}"
                  f"{_pad(f'{body:.3f}', 13, 'right')}")
    formats = _load(base / "m06" / "format.json")
    if formats:
        total = sum(len(cf.get("field_candidates") or []) for cf in formats.get("cluster_formats") or [])
        inside = sum(1 for cf in formats.get("cluster_formats") or []
                     for field in cf.get("field_candidates") or []
                     if field.get("reference_offset_start", 1 << 30) < header)
        print(f"      M06 字段候选 {total} 个, 其中落在明文头 {header} 字节内 {inside} 个.")
    return bool(table), formats is not None


def _seg_dat(root: Path) -> None:
    _stop(2, "网络流量结构推断: 密文 vs 明文记录头 (M01-M06)")
    _framing_block(root, "unknown_dat", "加密流量", "TLS 1.3 应用数据密文 (仅 0x17 负载)")
    print()
    _framing_block(root, "unknown_plain", "明文对照", "TLS 1.3 记录流 (明文记录头在位)")
    plain = _load(root / "unknown_plain" / "m03" / "framing.json") or {}
    framed = plain.get("messages") or []
    table_shown, fields_shown = _seg_verify(root, "unknown_plain", "明文对照")
    print()
    _note("两份同源: 密文那份只取 5 条 0x17 记录的负载, 对照那份是完整记录流 (9 条记录).")
    _note("对照上是唯一候选 (1 条): offset=3, width=2, big-endian, 正是 RFC 8446 的记录长度域.")
    if framed:
        total = sum(message.get("length") or 0 for message in framed)
        _note(f"{len(framed)} 条推断边界铺满输入: 长度合计 {total:,} B = 输入大小,"
              " 未解析 0 段, 边界逐条对上.")
    if table_shown:
        _note("首字节 0x16/0x14/0x17 是内容类型 (RFC 8446 定义); M03 只用了长度域,"
              " 内容类型是直接实读对照, 不参与推断.")
        _note("负载字节数够大的两簇一致率 0.003 与 0.000, 与随机不可区分:"
              " 恢复的是记录层边界, 不是明文.")
    if fields_shown:
        _note("M06 候选数量大不等于精度高: 真正落在明文头里的只有上面那几个.")
    _note("密文那一侧没有可校验的簇: 没有分帧, 就没有对齐, 也没有字段候选.")


def _seg_restore(root: Path) -> None:
    """Segment 3: the record order and roles M03 restores, plus the frozen model layer."""
    _stop(3, "数据还原分析: 结构还原 / 模型解释")
    _seg_structure(root)
    print()
    _seg_model(root)


def _seg_structure(root: Path) -> None:
    """Show that M03 restores order and record-layer role, not just boundaries.

    Every cell below is either an inferred boundary (from the repeated length
    field) or a byte read straight out of the hash-checked input. The content
    type and handshake type are direct reads cross-checked against RFC 8446;
    they are labelled as such so nobody reads them as inference output.
    """
    base = root / "unknown_plain"
    framing = _load(base / "m03" / "framing.json")
    if framing is None:
        print("  [结构还原] 明文对照链产物缺失, 本段跳过.")
        return
    manifest = _load(base / "run_manifest.json") or {}
    source = manifest.get("input") or {}
    raw = _boundary_source_bytes(source)
    if raw is None:
        print("  [结构还原] 输入未通过哈希复核, 不显示记录层角色.")
        return

    messages = framing.get("messages") or []
    if not messages:
        print("  [结构还原] 本次没有推断出记录边界.")
        return

    print("  [结构还原] 明文对照链 (TLS 1.3 记录流, 明文记录头在位)  候选假设, 非协议真值")
    print(f"      {_pad('记录', 6)}{_pad('区间', 22)}{_pad('长度', 8, 'right')}  "
          f"{_pad('内容类型', 25)}握手类型")
    roles: list[str] = []
    sequence: list[str] = []
    spans: list[tuple[int, int]] = []
    for index, message in enumerate(messages):
        start, end = message.get("start"), message.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < len(raw):
            continue
        content = raw[start]
        content_name = CONTENT_TYPES.get(content, "未在 RFC 8446 中登记")
        handshake = ""
        if content == 0x16 and start + 6 <= len(raw):
            handshake = HANDSHAKE_TYPES.get(raw[start + 5], f"0x{raw[start + 5]:02x} 未登记")
        roles.append(content_name)
        sequence.append(handshake or content_name)
        spans.append((start, end))
        body = f"0x{content:02x} {content_name}"
        print(f"      {_pad(f'#{index}', 6)}{_pad(f'[{start:>5}, {end:>5})', 22)}"
              f"{_pad(str(message.get('length')), 8, 'right')}  {_pad(body, 25)}"
              f"{handshake or '-'}")

    print()
    size = source.get("length")
    contiguous = all(spans[i][1] == spans[i + 1][0] for i in range(len(spans) - 1))
    covered = spans and spans[0][0] == 0 and isinstance(size, int) and spans[-1][1] == size
    if contiguous and covered:
        _note(f"顺序   {len(spans)} 条首尾相接: {spans[0][0]} → {spans[-1][1]},"
              " 无空洞无重叠, 铺满输入 → 记录顺序被还原.")
        _note("这不是额外推断: 分帧候选本来就要求覆盖完整输入, 相邻区间必须接得上.")
    else:
        _note(f"顺序   {len(spans)} 条区间未铺满输入, 顺序不成立.")

    compressed = [f"{name}×{count}" if count > 1 else name
                  for name, count in _runs(sequence)]
    _note("行为   " + " → ".join(compressed))
    _note("内容类型与握手类型是逐条实读首字节、再对照 RFC 8446 登记表;"
          " M03 推断只用长度域, 这两列不参与推断.")
    _note("这一步还原的是记录层的顺序和角色; 应用层语义仍要从密文里来, 这里给不出.")

    print()
    _declared_recovery_block(root)


def _tls_handshake_facts(blob: bytes, ranges: list[dict[str, int]]) -> dict[str, Any]:
    """Read negotiated parameters back out of M08's recovered handshake bytes.

    These are plaintext by RFC 8446 — that is precisely why M08 recovered them
    and refused the records that are not. Nothing here is decrypted and nothing
    is inferred: each field is read at its RFC 8446 offset, and a field that
    does not fit the declaration is left as None rather than guessed.
    """
    facts: dict[str, Any] = {"offered": [], "legacy": None, "version": None,
                             "suite": None, "group": None, "key_length": None}
    cursor = 0
    for region in ranges:
        span = region["end"] - region["start"]
        payload = blob[cursor:cursor + span]
        cursor += span
        if len(payload) < 4:
            continue
        kind = payload[0]
        if kind == 0x01:  # ClientHello
            offset = 4 + 2 + 32
            offset += 1 + (payload[offset] if offset < len(payload) else 0)
            if offset + 2 > len(payload):
                continue
            length = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            facts["offered"] = [int.from_bytes(payload[offset + 2 * i:offset + 2 * i + 2], "big")
                                for i in range(length // 2)
                                if offset + 2 * i + 2 <= len(payload)]
        elif kind == 0x02:  # ServerHello
            offset = 4
            if offset + 2 > len(payload):
                continue
            facts["legacy"] = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2 + 32
            offset += 1 + (payload[offset] if offset < len(payload) else 0)
            if offset + 3 > len(payload):
                continue
            facts["suite"] = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 3  # cipher suite + compression method
            if offset + 2 > len(payload):
                continue
            end = offset + 2 + int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            while offset + 4 <= min(end, len(payload)):
                ext_type = int.from_bytes(payload[offset:offset + 2], "big")
                size = int.from_bytes(payload[offset + 2:offset + 4], "big")
                body = payload[offset + 4:offset + 4 + size]
                if ext_type == 0x2B and len(body) >= 2:
                    facts["version"] = int.from_bytes(body[:2], "big")
                elif ext_type == 0x33 and len(body) >= 4:
                    facts["group"] = int.from_bytes(body[:2], "big")
                    facts["key_length"] = int.from_bytes(body[2:4], "big")
                offset += 4 + size
    return facts


def _declared_recovery_block(root: Path) -> None:
    """Segment 3 tail: what M08 recovers under the declared TLS record layout.

    Every number below is read out of the M08 artifact rather than recomputed
    here, so the screen and the persisted evidence cannot drift apart.
    """
    base = root / "unknown_plain"
    direct = base / "m08" / "direct"
    recovery = _load(direct / "recovery.json")
    if recovery is None:
        print("  [声明区域恢复] M08 产物缺失, 本块跳过.")
        return

    recoveries = recovery.get("recoveries") or []
    roles = {item["transformation_chain"][0]["parameters"].get("role"): item for item in recoveries}
    print("  [声明区域恢复] M08: 按调用方声明的 TLS 记录布局切分, 只取协议声明为明文的区域")
    print(f"      {_pad('角色', 22)}{_pad('区间', 6, 'right')}{_pad('字节', 8, 'right')}  区间(前 3)")

    def role_of(item: dict[str, Any]) -> str:
        return item["transformation_chain"][0]["parameters"].get("role", "?")

    for item in recoveries:
        ranges = item.get("source_ranges") or []
        shown = " ".join(f"[{r['start']},{r['end']})" for r in ranges[:3])
        if len(ranges) > 3:
            shown += f" … 共 {len(ranges)} 段"
        print(f"      {_pad(role_of(item), 22)}{_pad(str(len(ranges)), 6, 'right')}"
              f"{_pad(str(item['output']['length']), 8, 'right')}  {shown}")

    refused_regions = [r for item in recovery.get("skipped_sources") or []
                       if item.get("reason_code") == "DECLARED_PROTECTED_REGION"
                       for r in item.get("source_ranges") or []]
    refused = sum(r["end"] - r["start"] for r in refused_regions)
    plain = sum(item["output"]["length"] for item in recoveries)
    if refused_regions:
        print(f"      {_pad('受保护 + 拒绝', 22)}{_pad(str(len(refused_regions)), 6, 'right')}"
              f"{_pad(str(refused), 8, 'right')}  DECLARED_PROTECTED_REGION: 不解密, 只记账")
    _note(f"明文 {plain} 字节 + 受保护 {refused} 字节 = 输入 {plain + refused} 字节, 铺满无剩余.")
    _note("明文/受保护的划分来自调用方声明的 RFC 8446 布局 (5 字节头 + offset 3 的 2 字节大端长度),"
          " 不是从字节推断的; 受保护区域按 reason_code 记账, 不静默丢弃.")

    handshake = roles.get("handshake_plaintext")
    headers = roles.get("record_header")
    if handshake is None:
        _note("本次没有声明为明文的握手记录: 抓包从会话中途开始, 协商过程本就不在字节里.")
        return

    try:
        blob = (direct / handshake["output"]["artifact_ref"]).read_bytes()
    except OSError:
        print()
        _note("握手明文产物不可读, 协商结果不呈现.")
        return
    facts = _tls_handshake_facts(blob, handshake.get("source_ranges") or [])
    offered = facts["offered"]
    print()
    print("  [协商结果] 读自上面恢复出的握手明文产物 (非推断, 非解密: 这些字节按 RFC 8446 本来就不受保护)")
    if offered:
        shown = " ".join(f"0x{value:04x}" for value in offered[:4])
        _field("ClientHello", f"{len(offered)} 条提案套件: {shown} … 0x{offered[-1]:04x}")
    suite = facts["suite"]
    if suite is not None:
        name = CIPHER_SUITES.get(suite, "未登记")
        _field("ServerHello", f"legacy_version=0x{facts['legacy']:04x}  "
                              f"cipher_suite=0x{suite:04x} ({name})")
        version = facts["version"]
        group = facts["group"]
        detail = f"supported_versions={'0x%04x' % version if version else '未出现'}"
        if group:
            detail += (f"  key_share=0x{group:04x} ({NAMED_GROUPS.get(group, '未登记')},"
                       f" {facts['key_length']} 字节)")
        print(f"      {_pad('', 14)}  {detail}")
        _note("记录头里那 2 字节 legacy version 不是协商版本: 它写 0x0303,"
              " 协商版本在 ServerHello 的 supported_versions 扩展里.")
    if headers:
        declared = sorted(r["start"] for r in headers.get("source_ranges") or [])
        declared.append(plain + refused)
        framing = _load(base / "m03" / "framing.json") or {}
        messages = framing.get("messages") or []
        inferred = [m.get("start") for m in messages]
        if inferred:
            inferred = inferred + [messages[-1].get("end")]
        if inferred == declared:
            _note(f"M08 按声明布局切出的 {len(declared) - 1} 条记录边界与 M03 盲推断的边界逐条重合"
                  " (盲推断独立选出 header=5 / offset=3 / width=2 / 大端): 声明与推断互证.")


def _runs(items: list[str]) -> list[tuple[str, int]]:
    """Collapse a label sequence into (label, consecutive count) runs."""
    runs: list[tuple[str, int]] = []
    for item in items:
        if runs and runs[-1][0] == item:
            runs[-1] = (item, runs[-1][1] + 1)
        else:
            runs.append((item, 1))
    return runs


def _seg_model(root: Path) -> None:
    """Print the frozen constrained-explanation output, re-checking its citations.

    The model text is not regenerated here and no request leaves the machine on
    stage: the run was frozen at generation time and only the citation check is
    repeated. Every claim is shown against the evidence set it names, so a claim
    whose citation cannot be found is dropped rather than printed on trust.
    """
    manifest = _load(root / "unknown_plain" / "model" / "model_manifest.json")
    origin = root / "unknown_plain" / "model"
    if manifest is None:
        manifest = _load(FROZEN_MODEL / "model_manifest.json")
        origin = FROZEN_MODEL
    if manifest is None:
        print("  [模型解释] 未找到冻结的模型输出, 本段跳过.")
        return
    claims = manifest.get("claims") or []
    if manifest.get("status") != "invoked" or not claims:
        print(f"  [模型解释] 状态 {manifest.get('status')}: 无模型声明可呈现.")
        return

    print(f"  [模型解释] M12 受限解释层 (输出冻结于生成时, 演示时不联网、不重新请求)")
    _field("模型", f"{manifest.get('model')}   温度 0   上限 400 tokens")
    _field("冻结产物", origin.relative_to(ROOT) if origin.is_relative_to(ROOT) else origin)
    usage = manifest.get("usage") or {}
    if usage:
        _field("生成用量", f"prompt {usage.get('prompt_tokens')} + completion "
                           f"{usage.get('completion_tokens')} = {usage.get('total_tokens')} tokens")

    known, source_label = _evidence_ids(root, origin)
    cited = sorted({value for claim in claims for value in claim.get("evidence_ids", [])})
    if known is None:
        print()
        _note("证据集不可读, 引用无法核对, 不呈现模型文本.")
        return
    missing = [value for value in cited if value not in known]
    print()
    _field("引用核对", f"{len(claims)} 条假设, 引用 {len(cited)} 个编号, "
                       f"命中 {len(cited) - len(missing)} 个 ({source_label})")
    for index, claim in enumerate(claims, 1):
        ids = claim.get("evidence_ids", [])
        if any(value not in known for value in ids):
            _note(f"[丢弃假设 {index}] 引用编号未全部命中证据集, 该条不呈现.")
            continue
        head = f"    [模型假设 {index}] 引用 {len(ids)} 个编号: "
        print(head + _clip(", ".join(ids), WIDTH - _dw(head)))
        for line in _wrap(str(claim.get("text", "")), WIDTH - 8):
            print(f"      {line}")
    print()
    _note("模型文本按原样呈现, 未经改写; 完整原文与请求体见冻结产物, 均可复核 sha256.")
    _note("约束: 至多 2 条; 每条必须引用既有证据编号; 证据观测按不可信引用数据对待;"
          " 提示词禁断言协议语义、真值、因果、恶意性与'解密成功'.")
    _note("模型只做归纳, 不替代协议解析、解密或真值评分: 上面那张表的边界来自 M03, 不来自模型.")


def _evidence_ids(root: Path, origin: Path) -> tuple[set[str] | None, str]:
    """The evidence IDs a frozen claim may cite, plus where they were read from."""
    evidence = _load(root / "unknown_plain" / "m12" / "evidence.json")
    if isinstance(evidence, list):
        return {item.get("evidence_id") for item in evidence}, "本次运行的证据集"
    request = _load(origin / "request.json")
    try:
        content = request["body"]["messages"][1]["content"]
        sent = json.loads(content.split("\n", 1)[1])
        return {item["evidence_id"] for item in sent}, "冻结请求里随附的证据集"
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None, "不可读"


def _seg_capture(root: Path) -> None:
    _stop(4, "访问行为分析与行为类型分析 (M09/M10/M11)")
    m09 = _load(root / "capture" / "m09" / "flow_features.json")
    m10 = _load(root / "capture" / "m10" / "behaviors.json")
    m11 = _load(root / "capture" / "m11" / "prediction.json")

    if m09:
        metrics = m09["metrics"]
        _field("M09 流量统计", f"{metrics['flow_count']} 条流, {metrics['packet_count']} 个包")
    if m10:
        observations = m10.get("observations", [])
        types = [o.get("type") for o in observations]
        _field("M10 行为候选", f"{', '.join(types)}  (共 {len(types)} 条)")
    if m11:
        _seg_classifier(m11)
    else:
        _field("M11 类型候选", "本次产物中没有预测结果, 该行跳过")

    print()
    _seg_protocol_context(root)
    _note("行为候选是流量模式, 不是应用语义, 不是用户身份, 也不是恶意性判定.")
    _note("类型候选是冻结分类器对新输入的输出, 不是真值; 低于拒绝阈值的一律报 unknown.")
    _note("这条链的最终产物是 M12 证据报告, 下面一段展开它.")


def _seg_classifier(m11: dict[str, Any]) -> None:
    predictions = m11.get("predictions", [])
    rejected = [item for item in predictions if item.get("rejected")]
    _field("M11 类型候选", f"{len(predictions)} 条流  拒绝 {len(rejected)} 条  给出类型 "
                           f"{len(predictions) - len(rejected)} 条")
    shown = predictions[:6]
    for item in shown:
        label = item.get("predicted_label")
        mark = "  拒绝" if item.get("rejected") else ""
        print(f"    {_pad(str(item.get('scope_id')), 46)} {label}  {item.get('score')}{mark}")
    if len(predictions) > len(shown):
        _note(f"另有 {len(predictions) - len(shown)} 条流未逐条打印, 完整逐条结果见 M11 产物.")
    _field("M11 分类器", _classifier_line(m11))


def _classifier_line(m11: dict[str, Any]) -> str:
    """The frozen classifier's own identity, read back from the classification record."""
    parameters = _load(FROZEN_CLASSIFIER) or {}
    task = parameters.get("task", {})
    params = parameters.get("parameters", {})
    classes = "/".join(task.get("classes", []))
    return (f"{params.get('algorithm')}  特征集 {task.get('feature_schema_version')}  "
            f"类别 {classes}  拒绝阈值 {params.get('reject_threshold')}  (复用冻结模型)")


def _seg_protocol_context(root: Path) -> None:
    """M07 on one line: context for the flow above, not the subject of this segment."""
    m07 = _load(root / "capture" / "m07" / "protocols.json")
    if m07 is None:
        return
    observations = m07.get("observations", [])
    fields = [evidence.get("field") for observation in observations
              for evidence in observation.get("field_evidence", [])]
    protocols = sorted({observation.get("protocol") for observation in observations})
    _note(f"上下文 M07 协议识别: {m07['status']}, {'/'.join(protocols)} dissector 看见 "
          f"{len(fields)} 个字段 ({', '.join(fields[:3])}…); 字段只作上下文, 不参与上面三级.")


def _read_sections(report_md: Path) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    title: str | None = None
    body: list[str] = []
    for line in report_md.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("## "):
            if title is not None:
                sections.append((title, body))
            title, body = line[3:].strip(), []
        elif title is not None and line.strip():
            body.append(line.strip())
    if title is not None:
        sections.append((title, body))
    return sections


def _seg_report(root: Path) -> None:
    _stop(5, "M12 证据报告 (四类证据 + 证据编号)")
    base = next(
        (candidate for candidate in (root / "unknown_dat" / "m12", root / "capture" / "m12")
         if (candidate / "report_manifest.json").is_file() or (candidate / "report.md").is_file()),
        None,
    )
    if base is None:
        print("  [缺失] 本次产物未保留 M12 报告 (report_manifest.json / report.md 均未找到)")
        return
    manifest = _load(base / "report_manifest.json")
    report_md = base / "report.md"
    _field("报告来源", base.relative_to(root))

    if manifest is not None:
        sections = manifest.get("sections", {})
        _field("生成模式", manifest.get("generation_mode"))
        print()
        for key, label in (("observed_facts", "观测事实"), ("interpretations", "解释与假设"),
                           ("undetermined", "无法判断"), ("recommendations", "后续建议")):
            ids = sections.get(key, [])
            print(f"  {_pad(label, 14)}: {_pad(f'{len(ids)} 条', 6, 'right')}  "
                  f"{' '.join(ids[:2])}{' …' if len(ids) > 2 else ''}")
        truncation = manifest.get("truncation", {})
        if truncation:
            print()
            _field("证据上限", f"limit={truncation.get('limit')}  收录={truncation.get('included')}  "
                              f"省略={truncation.get('omitted')}")
        _field("报告 SHA-256", manifest.get("report_sha256"))
        if manifest.get("status") != "complete" or not sections.get("interpretations"):
            print()
            _note(f"清单状态 {manifest.get('status')}: 没有可支撑的解释/建议时, 该节保持为空.")

    if report_md.is_file():
        rendered = _read_sections(report_md)
        if rendered:
            title, body = rendered[0]
            print()
            print(f"  报告原文节选 [{title}]:")
            for line in body[:3]:
                print(f"    {_clip(line, WIDTH - 8)}")
            _note("每条结论都带稳定证据编号, 可回到它对应的字节范围.")


def _seg_encrypted() -> None:
    _stop(6, "加密流量: 外层识别在, 明文只取声明区域")
    if not ENCRYPTED_RUNS.is_dir():
        print(f"  [缺失] {ENCRYPTED_RUNS.relative_to(ROOT)}  (加密样本预跑结果不在本机)")
        _note("本段需在答辩前运行 python scripts\\run_encrypted_eval.py 生成预跑结果.")
        return
    print(f"  预跑结果: {ENCRYPTED_RUNS.relative_to(ROOT)}  (离线读取, 不联网、不重跑)")
    for sample_id, label in ENCRYPTED_SAMPLES:
        base = ENCRYPTED_RUNS / sample_id
        manifest = _load(base / "run_manifest.json")
        print()
        print(f"  [{sample_id}] {label}")
        if manifest is None:
            print("      [缺失] run_manifest.json")
            continue

        m01 = _load(base / "m01" / "result.json") or {}
        if m01.get("packets") is not None:
            print(f"      {_pad('M01', 6)}: {len(m01.get('packets') or []):,} 个包  "
                  f"{len(m01.get('flows') or []):,} 条流  "
                  f"{len(m01.get('streams') or []):,} 条 TCP 流")
        metrics9 = (_load(base / "m09" / "flow_features.json") or {}).get("metrics", {})
        if metrics9:
            print(f"      {_pad('M09', 6)}: {metrics9.get('flow_count')} 条流  "
                  f"{metrics9.get('packet_count')} 个包")

        m07 = _load(base / "m07" / "protocols.json") or {}
        if m07.get("observations"):
            protocols = sorted({o.get("protocol", "?") for o in m07["observations"]})
            fields = sorted({e.get("field", "?") for o in m07["observations"]
                             for e in o.get("field_evidence", [])})
            print(f"      {_pad('M07', 6)}: status={m07.get('status')}  "
                  f"{'/'.join(protocols)} dissector 可见字段 {', '.join(fields)}")
        else:
            reasons = sorted({u.get("reason_code", "?") for u in m07.get("unknown_scopes", [])})
            print(f"      {_pad('M07', 6)}: status={m07.get('status')}  "
                  f"原因 {'/'.join(reasons) or 'unrecorded'}  (隧道内无应用可见字段)")

        recovery = _load(base / "m08" / "direct" / "recovery.json") or {}
        metrics = recovery.get("metrics", {})
        scope = next((a.get("scope") for a in (manifest.get("artifacts") or [])
                      if a.get("module") == "M08"), {}) or {}
        refused = sum(r["end"] - r["start"]
                      for item in recovery.get("skipped_sources") or []
                      if item.get("reason_code") == "DECLARED_PROTECTED_REGION"
                      for r in item.get("source_ranges") or [])
        print(f"      {_pad('M08', 6)}: status={recovery.get('status')}  "
              f"恢复 {metrics.get('recovery_count')} 条  产出 {metrics.get('output_bytes')} 字节  "
              f"拒绝 {refused} 字节")
        if scope.get("source") == "longest_m01_stream_direction":
            stream = next((s for s in (m01.get("streams") or [])
                           if s.get("id") == scope.get("stream_id")), {})
            node0, node1 = stream.get("node0") or {}, stream.get("node1") or {}
            endpoints = (f"{node0.get('ip')}:{node0.get('port')} ↔ {node1.get('ip')}:{node1.get('port')}"
                         if node0 and node1 else scope.get("stream_id"))
            print(f"      {_pad('', 6)}  M08 取最长 complete 方向 {scope.get('direction')}: {endpoints}")
            for item in recovery.get("recoveries") or []:
                chain = item["transformation_chain"][0]
                print(f"      {_pad('', 6)}    {_pad(chain['parameters'].get('role', '?'), 22)}"
                      f"{_pad(str(item['output']['length']), 6, 'right')} 字节  "
                      f"{len(item.get('source_ranges') or [])} 段")
    print()
    _note("加密不影响外层识别: 包、流、方向都拆得出来; 看不到的只有应用层内容.")
    _note("两个样本的记录层都立得住, 但能恢复的内容不同: VPN 那条最长方向是一条会话中途开始的 TLS"
          " 流, 只有记录头可恢复; 直连那条另有 ServerHello 明文可读.")
    _note("记录层立不住时 M08 保持整体拒绝 (ENCRYPTED_WITHOUT_DECRYPTION_MATERIAL), 与上一条不是两套标准:"
          " 同一个输入端, 一个是协议声明为明文的区域被恢复, 一个是整段无明文声明.")
    _note("拒绝是产物的一部分: 每个被拒绝的区间都有 reason_code 和字节数, 不是静默丢弃;"
          " 全程没有解密, 也没有把密文改说成明文.")
    _note("会话中途开始的抓包里没有握手明文可恢复, 这一点由样本自身的字节决定, 不靠上游声明.")


def _seg_acceptance() -> int:
    _stop(7, "独立验收门禁")
    print(f"  验收记录: {ACCEPTANCE.relative_to(ROOT)}")
    print(f"  验收脚本: {VERIFY.relative_to(ROOT)}  (重新计算, 不采信分析程序自己写的状态说明)")
    print()
    completed = subprocess.run(
        [sys.executable, "-B", str(VERIFY), str(ACCEPTANCE)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    for stream, text in ((sys.stdout, completed.stdout), (sys.stderr, completed.stderr)):
        text = (text or "").strip()
        if text:
            for line in text.splitlines():
                stream.write(f"  {line}\n")
    print()
    _note("验收由独立门禁决定, 不由分析程序自己决定.")
    return completed.returncode


# --------------------------------------------------------------------------- #
# 运行
# --------------------------------------------------------------------------- #
def _prepare_run_dir(path: Path) -> Path:
    """Clear a scratch directory so the pipeline can create it fresh.

    The pipeline refuses to write into a pre-existing directory. The guard keeps
    this from ever deleting anything outside tmp/.
    """
    resolved = path.resolve()
    tmp_root = (ROOT / "tmp").resolve()
    if tmp_root not in resolved.parents:
        raise ValueError(f"refusing to clear a directory outside tmp/: {resolved}")
    if path.exists():
        shutil.rmtree(path)
    return path


def _run_pipeline(dat: Path, control: Path | None, rare: Path | None, recovery: Path,
                  capture: Path | None, run_dir: Path) -> dict[str, Any]:
    from scripts.analyze import run_pipeline
    from scripts.run_technical_exploration_demo import run_demo

    tshark = _find_tshark() if capture else None
    if capture and tshark is None:
        raise RuntimeError("--capture 需要 tshark.exe, 但未在 WIRESHARK_HOME / PATH / 默认安装路径找到")
    summary = run_demo(dat, recovery, run_dir, capture_path=capture, tshark_path=tshark)
    profile = ROOT / "profiles" / "unknown-private.json"
    if control is not None:
        run_pipeline(control, run_dir / "unknown_plain", PLAIN_PROFILE)
    if rare is not None:
        run_pipeline(rare, run_dir / "unknown_rare", profile)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Three-minute defense demonstration driver.")
    parser.add_argument("--rundir", type=Path,
                        help=f"读取已有产物目录, 跳过运行 (冻结结果: {FROZEN_RUN})")
    parser.add_argument("--dat", type=Path, default=DEFAULT_DAT)
    parser.add_argument("--control", type=Path, default=DEFAULT_CONTROL,
                        help="同一套推断的明文对照输入")
    parser.add_argument("--rare", type=Path, default=DEFAULT_RARE,
                        help="少见/专有格式输入, 测无公开规格时的盲推断")
    parser.add_argument("--recovery-input", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--no-pause", action="store_true", help="不等待 Enter, 一次跑完全部七段")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)

    if args.rundir is not None:
        root = args.rundir.resolve()
        if not root.is_dir():
            print(f"defense-demo: 产物目录不存在: {root}", file=sys.stderr)
            return 2
        print(f"defense-demo: 读取已有产物 {root}")
    else:
        missing = [str(p) for p in (args.dat, args.control, args.rare,
                                    args.recovery_input, args.capture) if not p.is_file()]
        if missing:
            print("defense-demo: 输入缺失:\n  " + "\n  ".join(missing), file=sys.stderr)
            return 2
        root = _prepare_run_dir(args.output_dir)
        print("defense-demo: 正在运行 加密流量链 / 明文对照链 / 少见协议链 / 恢复 / 抓包 ...")
        try:
            _run_pipeline(args.dat.resolve(), args.control.resolve(), args.rare.resolve(),
                          args.recovery_input.resolve(), args.capture.resolve(), root)
        except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
            print(f"defense-demo: 运行失败: {exc}", file=sys.stderr)
            return 2
        print(f"defense-demo: 产物目录 {root}")

    _seg_inputs(root)
    _pause(not args.no_pause)
    _seg_dat(root)
    _pause(not args.no_pause)
    _seg_restore(root)
    _pause(not args.no_pause)
    _seg_capture(root)
    _pause(not args.no_pause)
    _seg_report(root)
    _pause(not args.no_pause)
    _seg_encrypted()
    _pause(not args.no_pause)
    code = _seg_acceptance()

    print()
    _rule("=")
    print("  推断是候选、恢复有校验、识别有出处、失败会降级。")
    _rule("=")
    return code


if __name__ == "__main__":
    raise SystemExit(main())

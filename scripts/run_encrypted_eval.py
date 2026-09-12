#!/usr/bin/env python3
"""Visible end-to-end analysis of encrypted binary network captures.

This driver runs the real ``scripts/analyze.py`` entry point over two encrypted
captures -- one VPN-tunnelled session and one direct TLS 1.3 session -- and
prints a per-stage evidence table plus a cross-sample summary.

It deliberately shows honest module statuses: a stage that legitimately has
nothing to report (for example plaintext recovery over ciphertext) is displayed
with its true status instead of being hidden or rewritten.

Usage:
    python scripts/run_encrypted_eval.py
    python scripts/run_encrypted_eval.py --keep   # keep previous run dirs used above
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORK_ROOT = ROOT / "tmp" / "encrypted-eval"
SAMPLES_DIR = WORK_ROOT / "samples"
RUNS_DIR = WORK_ROOT / "runs"
PROFILE = ROOT / "profiles" / "encrypted-full.json"
ANALYZE = ROOT / "scripts" / "analyze.py"

TLS_URL = (
    "https://gitlab.com/wireshark/wireshark/-/raw/"
    "cdfb6721e77c19d43f4787f66e9d5f2525281a22/test/captures/tls13-rfc8446.pcap"
)

SAMPLES: list[dict[str, Any]] = [
    {
        "id": "iscx-vpn-skype-audio1",
        "file": "vpn_skype_audio1.pcap",
        "kind": "VPN 隧道加密",
        "source": "ISCX VPN-nonVPN 2016 (UNB CIC) / vpn_skype_audio1.pcap",
        "note": "Skype 音频经 VPN 隧道封装，应用层载荷不可直接读取",
        "local": [
            "tmp/iscx-work/capped/vpn_skype_audio1.pcap",
            "tmp/kaggle/iscx-vpn/vpn_skype_audio1.pcap",
        ],
        "url": None,
    },
    {
        "id": "tls13-rfc8446",
        "file": "tls13-rfc8446.pcap",
        "kind": "直连 TLS 1.3 加密",
        "source": "Wireshark 4.6.0 test suite @ cdfb6721 / tls13-rfc8446.pcap",
        "note": "未封装的标准 TLS 1.3 会话，含握手与加密应用数据",
        "local": [],
        "url": TLS_URL,
    },
]

STAGE_ORDER = ["M01", "M02", "M07", "M08", "M09", "M10", "M11", "M11_PREDICTION", "M12"]

STATUS_LABEL = {
    "completed": "completed",
    "reused_verified": "reused_verified",
    "partial": "partial",
    "blocked": "blocked",
    "failed": "failed",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def _find_tshark() -> Path | None:
    import os

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


def _ensure_sample(spec: dict[str, Any]) -> tuple[Path, str]:
    """Return (path, provenance). Uses a local copy when available, else downloads."""
    target = SAMPLES_DIR / spec["file"]
    if target.is_file():
        return target, "本地已有"
    for rel in spec["local"]:
        source = ROOT / rel
        if source.is_file():
            SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            return target, f"本地复制自 {rel}"
    if not spec["url"]:
        raise FileNotFoundError(f"no local copy and no download URL for {spec['file']}")
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(spec["url"], timeout=60) as response:  # noqa: S310
        target.write_bytes(response.read())
    return target, "下载自固定提交"


def _fresh(path: Path) -> Path:
    """Clear a scratch output dir so analyze.py can create it fresh.

    analyze.py refuses to write into a pre-existing directory, and the guard
    stops this from ever deleting anything outside WORK_ROOT.
    """
    resolved = path.resolve()
    if WORK_ROOT.resolve() not in resolved.parents:
        raise ValueError(f"refusing to clear a directory outside {WORK_ROOT}: {resolved}")
    if path.exists():
        shutil.rmtree(path)
    failure = path.parent / f"{path.name}.failure.json"
    if failure.is_file():
        failure.unlink()
    return path


def _run_analyze(sample: Path, outdir: Path, tshark: Path | None) -> int:
    command = [sys.executable, "-B", str(ANALYZE), "--input", str(sample),
               "--profile", str(PROFILE), "--output-dir", str(outdir)]
    if tshark:
        command += ["--tshark", str(tshark)]
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", check=False)
    if completed.returncode != 0:
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
    return completed.returncode


def _artifact(manifest: dict[str, Any], module: str) -> Path | None:
    for item in manifest.get("artifacts", []):
        if item.get("module") == module:
            return Path(item["path"])
    return None


def _evidence(module: str, manifest: dict[str, Any]) -> str:
    path = _artifact(manifest, module)
    if path is None or not path.is_file():
        return "-"
    data = _load(path)
    if module == "M01":
        return (f"format={data.get('format')} "
                f"packets={len(data.get('packets', []))} "
                f"flows={len(data.get('flows', []))} "
                f"streams={len(data.get('streams', []))}")
    if module == "M02":
        glob = data.get("global", {})
        return (f"len={glob.get('length')} "
                f"H={glob.get('entropy_bits_per_byte'):.3f} "
                f"ascii={glob.get('printable_ascii_ratio'):.3f} "
                f"windows={len(data.get('windows', []))}")
    if module == "M07":
        observations = data.get("observations", [])
        counts = Counter(o.get("protocol", "?") for o in observations)
        if counts:
            top = ", ".join(f"{name}x{n}" for name, n in counts.most_common(4))
            return f"status={data.get('status')} {len(observations)} 观测: {top}"
        reasons = sorted({u.get("reason_code", "?") for u in data.get("unknown_scopes", [])})
        return (f"status={data.get('status')} 0 观测 "
                f"(reason={'/'.join(reasons) or 'unrecorded'})")
    if module == "M08":
        metrics = data.get("metrics", {})
        return f"status={data.get('status')} recovered={metrics.get('recovery_count')}"
    if module == "M09":
        metrics = data.get("metrics", {})
        return f"flows={metrics.get('flow_count')} packets={metrics.get('packet_count')} status={data.get('status')}"
    if module == "M10":
        counts = Counter(o.get("type", "?") for o in data.get("observations", []))
        top = ", ".join(f"{name}x{n}" for name, n in counts.most_common(4)) or "无"
        return f"flows={data.get('metrics', {}).get('flow_count')} 行为: {top}"
    if module == "M11":
        task = data.get("task", {})
        return f"复用分类器 classes={task.get('classes')} fv={task.get('feature_schema_version')}"
    if module == "M11_PREDICTION":
        predictions = data.get("predictions", [])
        counts = Counter(p.get("predicted_label", "?") for p in predictions)
        top = ", ".join(f"{name}x{n}" for name, n in counts.most_common(4)) or "无"
        peak = max((p.get("score", 0.0) for p in predictions), default=0.0)
        return f"n={len(predictions)} 预测: {top} 最高分={peak:.3f}"
    if module == "M12":
        sections = data.get("sections", {})
        return (f"证据: 事实{len(sections.get('observed_facts', []))} "
                f"解释{len(sections.get('interpretations', []))} "
                f"待定{len(sections.get('undetermined', []))} "
                f"建议{len(sections.get('recommendations', []))}")
    return "-"


def _print_sample_header(spec: dict[str, Any], sample: Path, provenance: str) -> None:
    size = sample.stat().st_size
    print()
    print("=" * 100)
    print(f"样本: {spec['id']}  [{spec['kind']}]")
    print("-" * 100)
    print(f"  来源    : {spec['source']}")
    print(f"  说明    : {spec['note']}")
    print(f"  文件    : {sample}  ({provenance})")
    print(f"  大小    : {size:,} 字节")
    print(f"  SHA-256 : {_sha256(sample)}")
    print("=" * 100)


def _print_stage_table(manifest: dict[str, Any]) -> None:
    records = {item["stage"]: item for item in manifest.get("stages", [])}
    rows: list[tuple[str, str, str, str]] = []
    for stage in STAGE_ORDER:
        record = records.get(stage)
        if record is None:
            rows.append((stage, "not_selected", "-", "-"))
            continue
        status = STATUS_LABEL.get(record.get("status"), record.get("status", "?"))
        elapsed = record.get("elapsed_seconds")
        took = f"{elapsed:.2f}" if isinstance(elapsed, (int, float)) else "-"
        reason = record.get("reason") or ""
        evidence = _evidence(stage, manifest)
        if reason:
            evidence = f"{evidence}  | {reason}"
        rows.append((stage, status, took, evidence))

    w_stage = max(len("Stage"), *(len(r[0]) for r in rows))
    w_status = max(len("Status"), *(len(r[1]) for r in rows))
    w_time = max(len("Time(s)"), *(len(r[2]) for r in rows))
    print(f"  {'Stage'.ljust(w_stage)}  {'Status'.ljust(w_status)}  {'Time(s)'.rjust(w_time)}  Evidence")
    print(f"  {'-' * w_stage}  {'-' * w_status}  {'-' * w_time}  {'-' * 40}")
    for stage, status, took, evidence in rows:
        print(f"  {stage.ljust(w_stage)}  {status.ljust(w_status)}  {took.rjust(w_time)}  {evidence}")
    print()
    print(f"  运行清单状态 : {manifest.get('status')}")
    print(f"  总耗时       : {manifest.get('elapsed_seconds')} 秒")
    input_info = manifest.get("input", {})
    print(f"  输入哈希     : {input_info.get('sha256')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="do not clear previous run directories")
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    tshark = _find_tshark()
    print("加密流量二进制分析 —— 全链路可见性评测")
    print(f"  项目根目录 : {ROOT}")
    print(f"  Profile    : {PROFILE.relative_to(ROOT)}")
    print(f"  TShark     : {tshark if tshark else '未找到（M01/M07 将不可用）'}")

    summaries: list[dict[str, Any]] = []
    for spec in SAMPLES:
        try:
            sample, provenance = _ensure_sample(spec)
        except (OSError, FileNotFoundError, urllib.error.URLError) as exc:
            print(f"\n[跳过] {spec['id']}: {exc}")
            summaries.append({"id": spec["id"], "ok": False, "detail": str(exc)})
            continue

        _print_sample_header(spec, sample, provenance)
        outdir = RUNS_DIR / spec["id"]
        if args.keep and outdir.exists():
            print(f"\n[跳过] 输出已存在（--keep）：{outdir}")
            summaries.append({"id": spec["id"], "ok": False, "detail": "output exists"})
            continue
        _fresh(outdir)

        print(f"\n  [运行] python scripts/analyze.py --input {spec['file']} "
              f"--profile profiles/encrypted-full.json --output-dir ...")
        code = _run_analyze(sample, outdir, tshark)
        manifest_path = outdir / "run_manifest.json"
        if code != 0 or not manifest_path.is_file():
            failure = outdir.parent / f"{outdir.name}.failure.json"
            detail = f"analyze 退出码 {code}"
            if failure.is_file():
                detail += f"; {_load(failure).get('error', {}).get('message', '')}"
            print(f"  [失败] {detail}")
            summaries.append({"id": spec["id"], "ok": False, "detail": detail})
            continue

        manifest = _load(manifest_path)
        _print_stage_table(manifest)
        summaries.append({
            "id": spec["id"], "ok": True, "status": manifest.get("status"),
            "kind": spec["kind"], "size": sample.stat().st_size,
        })

    print()
    print("=" * 100)
    print("汇总")
    print("-" * 100)
    for item in summaries:
        if item["ok"]:
            print(f"  [OK]   {item['id']:<26} 类型={item['kind']:<14} "
                  f"大小={item['size']:>10,}  清单状态={item['status']}")
        else:
            print(f"  [FAIL] {item['id']:<26} {item['detail']}")
    ok = all(item["ok"] for item in summaries) and summaries
    print("=" * 100)
    print("结论: " + ("两个加密样本均完成全链路分析（含诚实的不可恢复状态）" if ok else "存在未完成的样本"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

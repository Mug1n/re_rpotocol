#!/usr/bin/env python3
"""Produce one evidence-bound demonstration for the technical exploration topic.

The command deliberately separates three claims: unknown-DAT structure hypotheses,
strictly validated recoverable content, and capture-derived protocol/behavior evidence.
It never treats a successful decode as proof of application semantics or treats
encrypted TLS/SSH bytes as plaintext without decryption material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.M08.run import analyze_recovery
from scripts.analyze import run_pipeline


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_report(path: Path, summary: dict[str, Any]) -> None:
    capture = summary["capture"]
    lines = [
        "# 技术探索题专项演示结果",
        "",
        "## 输入",
        "",
        f"- 未知 DAT：`{summary['dat']['path']}`（SHA-256：`{summary['dat']['sha256']}`）",
        f"- 恢复输入：`{summary['recovery_input']['path']}`（SHA-256：`{summary['recovery_input']['sha256']}`）",
        "",
        "## 未知 DAT 分析",
        "",
        "已运行 M01--M06 与 M12：内容探测、特征、自动分帧、聚类、对齐、字段候选和证据报告。"
        "边界、类型组与字段均是可审计候选，不是协议语义真值。",
        "",
        "## 数据恢复",
        "",
        f"M08 状态：`{summary['recovery']['status']}`；恢复候选数：{summary['recovery']['recovery_count']}。",
        "仅记录通过 UTF-8/UTF-16、Hex、Base64、gzip/zlib 完整性验证的恢复链。"
        "TLS/SSH 等加密内容若没有显式解密材料，会被标记为不可恢复，而不是伪造明文。",
        "",
        "## 抓包协议与访问行为",
        "",
    ]
    if capture["status"] == "not_requested":
        lines.append("未提供抓包；因此本次没有协议识别或访问行为输出。")
    else:
        lines.extend([
            f"抓包状态：`{capture['status']}`。",
            "已运行 M01、M02、M07、M09、M10 与 M12；M07 只使用 TShark 实际可见的标准协议字段，"
            "M09/M10 只报告流量统计和行为候选。",
        ])
    lines.extend([
        "",
        "## 大模型边界",
        "",
        "若使用 `--invoke-model` 且进程显式提供 `DEEPSEEK_API_KEY`，模型只能基于 M12 的哈希绑定证据生成带引用说明；"
        "模型不会替代协议解析、解密或真值评分。",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_demo(
    dat_path: str | Path,
    recovery_input: str | Path,
    output_dir: str | Path,
    *,
    capture_path: str | Path | None = None,
    tshark_path: str | Path | None = None,
    invoke_model: bool = False,
) -> dict[str, Any]:
    dat, recovery_source, destination = Path(dat_path), Path(recovery_input), Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    for label, path in (("DAT", dat), ("recovery input", recovery_source)):
        if not path.is_file():
            raise FileNotFoundError(f"{label} does not exist or is not a file: {path}")
    if capture_path is not None and not Path(capture_path).is_file():
        raise FileNotFoundError(f"capture does not exist or is not a file: {capture_path}")
    if capture_path is not None and tshark_path is None:
        raise ValueError("--capture requires --tshark for reproducible protocol recognition")

    destination.mkdir(parents=True)
    try:
        dat_manifest = run_pipeline(
            dat, destination / "unknown_dat", ROOT / "profiles" / "unknown-private.json",
            invoke_model=invoke_model,
        )
        recovery = analyze_recovery(
            recovery_source, destination / "recovery", source_module="course_fixture",
            source_record_id=recovery_source.name,
        )
        capture: dict[str, Any] = {"status": "not_requested"}
        if capture_path is not None:
            capture_manifest = run_pipeline(
                capture_path, destination / "capture", ROOT / "profiles" / "course-capture-observability.json",
                tshark_path=tshark_path,
            )
            capture = {
                "status": capture_manifest["status"],
                "path": str(capture_path),
                "sha256": _sha256(Path(capture_path)),
                "manifest": "capture/run_manifest.json",
            }
        summary = {
            "schema_version": "0.1",
            "status": "complete",
            "dat": {"path": str(dat), "sha256": _sha256(dat), "manifest": "unknown_dat/run_manifest.json"},
            "recovery_input": {"path": str(recovery_source), "sha256": _sha256(recovery_source)},
            "recovery": {
                "status": recovery["status"],
                "recovery_count": recovery["metrics"]["recovery_count"],
                "manifest": "recovery/recovery.json",
            },
            "capture": capture,
            "limitations": [
                "Unknown-DAT framing, message groups, and field boundaries are hypotheses unless independently scored.",
                "Successful decoding/decompression does not establish application semantics.",
                "Encrypted payload plaintext requires explicit decryption material and is otherwise reported as unavailable.",
            ],
        }
        _write_json(destination / "technical_exploration_summary.json", summary)
        _write_report(destination / "technical_exploration_report.md", summary)
        return summary
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the course technical-exploration demonstration.")
    parser.add_argument("--dat", type=Path, required=True, help="Provided unknown .dat binary input")
    parser.add_argument("--recovery-input", type=Path, required=True, help="Bounded recoverable-content input")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--capture", type=Path, help="Optional capture for protocol and behavior analysis")
    parser.add_argument("--tshark", type=Path, help="Explicit tshark.exe; required with --capture")
    parser.add_argument("--invoke-model", action="store_true", help="Use DeepSeek only when DEEPSEEK_API_KEY is explicitly available")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_demo(args.dat, args.recovery_input, args.output_dir, capture_path=args.capture,
                 tshark_path=args.tshark, invoke_model=args.invoke_model)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"technical-demo: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "technical_exploration_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

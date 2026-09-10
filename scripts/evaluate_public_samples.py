#!/usr/bin/env python3
"""Evaluate the frozen public sample corpus and write evidence-bounded reports."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "external" / "test-samples-manifest.json"
HEX_LINE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
EVALUATION_M02_WINDOW_SIZE = 64 * 1024


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_modules() -> dict[str, Any]:
    return {
        module: load_module(
            f"public_sample_{module.lower()}", ROOT / "experiments" / module / "run.py"
        )
        for module in [f"M{index:02d}" for index in range(1, 13)]
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_hex_messages(path: Path) -> list[bytes]:
    messages = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        if HEX_LINE.fullmatch(line) is None:
            raise ValueError(f"invalid hexadecimal message at line {line_number}")
        messages.append(bytes.fromhex(line))
    if not messages:
        raise ValueError("hex message source contains no messages")
    return messages


def _module(status: str, detail: str, **metrics: Any) -> dict[str, Any]:
    return {"status": status, "detail": detail, "metrics": metrics}


def _failure(exc: Exception) -> dict[str, Any]:
    return _module("failed", f"{type(exc).__name__}: {exc}")


def _run_step(
    result: dict[str, Any],
    module: str,
    operation: Callable[[], tuple[dict[str, Any], str, dict[str, Any]]],
) -> dict[str, Any] | None:
    try:
        artifact, detail, metrics = operation()
    except Exception as exc:  # Reports must survive one module failure.
        result["modules"][module] = _failure(exc)
        result["limitations"].append(f"{module} failed: {type(exc).__name__}: {exc}")
        return None
    result["modules"][module] = _module(str(artifact.get("status", "ok")), detail, **metrics)
    return artifact


def _base_result(dataset: dict[str, Any], artifact: dict[str, Any], input_path: Path) -> dict[str, Any]:
    return {
        "artifact_id": artifact["artifact_id"],
        "protocol": artifact["protocol"],
        "category": dataset["category"],
        "dataset_id": dataset["dataset_id"],
        "input_path": artifact["path"],
        "input_sha256": sha256(input_path),
        "input_size": input_path.stat().st_size,
        "outcome": "completed",
        "modules": {},
        "highlights": [],
        "limitations": [],
    }


def _m01_step(
    modules: dict[str, Any], input_path: Path, output: Path,
    *, tshark_path: Path | None = None,
):
    artifact = modules["M01"].analyze_input(
        input_path, output, tshark_path=tshark_path
    )
    detail = (
        f"detected {artifact['format']}; packets={len(artifact['packets'])}, "
        f"flows={len(artifact['flows'])}, streams={len(artifact['streams'])}"
    )
    return artifact, detail, {
        "format": artifact["format"],
        "packet_count": len(artifact["packets"]),
        "flow_count": len(artifact["flows"]),
        "stream_count": len(artifact["streams"]),
        "warning_count": len(artifact["warnings"]),
    }


def _m02_step(modules: dict[str, Any], input_path: Path, output: Path):
    artifact = modules["M02"].analyze_file(
        input_path,
        output,
        window_size=EVALUATION_M02_WINDOW_SIZE,
        window_step=EVALUATION_M02_WINDOW_SIZE,
    )
    global_features = artifact["global"]
    detail = (
        f"entropy={global_features['entropy_bits_per_byte']}; "
        f"printable={global_features['printable_ascii_ratio']}; "
        f"zero={global_features['zero_ratio']}"
    )
    return artifact, detail, {
        "length": global_features["length"],
        "entropy_bits_per_byte": global_features["entropy_bits_per_byte"],
        "printable_ascii_ratio": global_features["printable_ascii_ratio"],
        "zero_ratio": global_features["zero_ratio"],
    }


def _largest_stream_direction(m01: dict[str, Any], m01_dir: Path) -> tuple[Path, dict[str, Any], str] | None:
    candidates = []
    for stream in m01["streams"]:
        for direction in stream["directions"]:
            candidates.append((int(direction["length"]), direction, str(stream["id"])))
    if not candidates:
        return None
    _, direction, stream_id = max(candidates, key=lambda item: item[0])
    return m01_dir / direction["artifact_ref"], direction, stream_id


def evaluate_capture(
    dataset: dict[str, Any],
    artifact: dict[str, Any],
    input_path: Path,
    work_dir: Path,
    modules: dict[str, Any],
    *,
    tshark_path: Path | None = None,
) -> dict[str, Any]:
    result = _base_result(dataset, artifact, input_path)
    m01_dir = work_dir / "m01"
    m01 = _run_step(
        result, "M01",
        lambda: _m01_step(modules, input_path, m01_dir, tshark_path=tshark_path),
    )
    m02_dir = work_dir / "m02"
    m02 = _run_step(result, "M02", lambda: _m02_step(modules, input_path, m02_dir))
    if m01 is None:
        for name in ("M07", "M08", "M09", "M10", "M12"):
            result["modules"][name] = _module("not_run", "M01 prerequisite failed")
        return _finalize(result)

    m01_path = m01_dir / "result.json"
    m07_dir = work_dir / "m07"

    def run_m07():
        value = modules["M07"].analyze_protocols(
            m01_path, m07_dir, tshark_path=tshark_path
        )
        protocols = sorted({str(item["protocol"]) for item in value["observations"]})
        detail = (
            f"observations={len(value['observations'])}; protocols="
            f"{', '.join(protocols) if protocols else 'none approved'}"
        )
        return value, detail, {
            "observation_count": len(value["observations"]),
            "unknown_scope_count": len(value["unknown_scopes"]),
            "protocols": protocols,
        }

    m07 = _run_step(result, "M07", run_m07)
    if m07:
        protocols = result["modules"]["M07"]["metrics"]["protocols"]
        if protocols:
            result["highlights"].append("Approved protocol evidence: " + ", ".join(protocols))
        else:
            result["limitations"].append("M07 found no fields from its approved protocol whitelist.")

    stream = _largest_stream_direction(m01, m01_dir)
    m08 = None
    if stream is None:
        result["modules"]["M08"] = _module(
            "not_applicable", "no reassembled TCP direction was available"
        )
    else:
        stream_path, direction, stream_id = stream
        m08_dir = work_dir / "m08"

        def run_m08():
            value = modules["M08"].analyze_recovery(
                stream_path,
                m08_dir,
                expected_sha256=direction["sha256"],
                source_module="M01",
                source_record_id=stream_id,
            )
            detail = (
                f"largest TCP direction={direction['length']} bytes; "
                f"recoveries={len(value['recoveries'])}; skipped={len(value['skipped_sources'])}"
            )
            return value, detail, {
                "input_length": direction["length"],
                "recovery_count": len(value["recoveries"]),
                "skipped_count": len(value["skipped_sources"]),
            }

        m08 = _run_step(result, "M08", run_m08)

    m09_dir = work_dir / "m09"

    def run_m09():
        value = modules["M09"].analyze(m01_path, m09_dir)
        metrics = value["metrics"]
        return value, (
            f"flows={metrics['flow_count']}; packets={metrics['packet_count']}; "
            f"unavailable={len(value['unavailable_features'])}"
        ), {**metrics, "unavailable_feature_count": len(value["unavailable_features"])}

    m09 = _run_step(result, "M09", run_m09)
    m10 = None
    if m09 is None:
        result["modules"]["M10"] = _module("not_run", "M09 prerequisite failed")
    else:
        m10_dir = work_dir / "m10"

        def run_m10():
            value = modules["M10"].analyze(m09_dir / "flow_features.json", m10_dir)
            types = sorted({str(item["type"]) for item in value["observations"]})
            return value, (
                f"observations={len(value['observations'])}; patterns="
                f"{', '.join(types) if types else 'none'}"
            ), {
                **value["metrics"],
                "patterns": types,
                "insufficient_scope_count": len(value["insufficient_scopes"]),
            }

        m10 = _run_step(result, "M10", run_m10)
        if m10 and result["modules"]["M10"]["metrics"]["patterns"]:
            result["highlights"].append(
                "Traffic patterns (not application labels): "
                + ", ".join(result["modules"]["M10"]["metrics"]["patterns"])
            )

    result["modules"]["M11"] = _module(
        "not_applicable", "no behavior labels and leakage-safe collection groups"
    )

    m12_inputs: dict[str, Path] = {"M01": m01_path}
    if m02 is not None:
        m12_inputs["M02"] = m02_dir / "features.json"
    if m07 is not None:
        m12_inputs["M07"] = m07_dir / "protocols.json"
    if m08 is not None:
        m12_inputs["M08"] = work_dir / "m08" / "recovery.json"
    if m09 is not None:
        m12_inputs["M09"] = m09_dir / "flow_features.json"
    if m10 is not None:
        m12_inputs["M10"] = work_dir / "m10" / "behaviors.json"
    m12_dir = work_dir / "m12"

    def run_m12():
        value = modules["M12"].build_report(m12_inputs, m12_dir)
        evidence = json.loads((m12_dir / "evidence.json").read_text(encoding="utf-8"))
        return value, f"evidence_records={len(evidence)}; report_status={value['status']}", {
            "evidence_count": len(evidence),
            "input_module_count": len(m12_inputs),
        }

    _run_step(result, "M12", run_m12)
    return _finalize(result)


def _write_length_prefixed_stream(messages: list[bytes], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        for message in messages:
            stream.write(len(message).to_bytes(4, "big"))
            stream.write(message)


def evaluate_hex_messages(
    dataset: dict[str, Any],
    artifact: dict[str, Any],
    input_path: Path,
    work_dir: Path,
    modules: dict[str, Any],
) -> dict[str, Any]:
    result = _base_result(dataset, artifact, input_path)
    m01_dir = work_dir / "m01"
    m01 = _run_step(result, "M01", lambda: _m01_step(modules, input_path, m01_dir))
    messages = decode_hex_messages(input_path)
    derived_stream = work_dir / "derived" / "u32be-length-prefixed.bin"
    _write_length_prefixed_stream(messages, derived_stream)
    result["highlights"].append(
        f"Decoded {len(messages)} Hex messages; derived stream adds an explicit u32be payload length."
    )
    result["limitations"].append(
        "M03 boundaries come from the evaluation wrapper, not from an inferred native protocol field."
    )
    m02_dir = work_dir / "m02"
    m02 = _run_step(result, "M02", lambda: _m02_step(modules, derived_stream, m02_dir))
    m03_dir = work_dir / "m03"

    def run_m03():
        value = modules["M03"].analyze_file(
            derived_stream,
            m03_dir,
            rule="length",
            parameters={
                "magic": b"",
                "length_offset": 0,
                "length_width": 4,
                "byteorder": "big",
                "length_mode": "payload",
                "header_size": 4,
                "trailer_size": 0,
                "start_offset": 0,
                "max_frame_length": 1024 * 1024,
            },
        )
        return value, (
            f"messages={len(value['messages'])}; unparsed_ranges={len(value['unparsed_ranges'])}; "
            "boundary_basis=derived u32be length"
        ), {
            "message_count": len(value["messages"]),
            "unparsed_range_count": len(value["unparsed_ranges"]),
        }

    m03 = _run_step(result, "M03", run_m03)
    m04 = m05 = m06 = None
    if m03 is None:
        for name in ("M04", "M05", "M06"):
            result["modules"][name] = _module("not_run", "M03 prerequisite failed")
    else:
        m04_dir = work_dir / "m04"

        def run_m04():
            value = modules["M04"].analyze_framing(m03_dir / "framing.json", m04_dir)
            metrics = value["metrics"]
            return value, (
                f"clusters={metrics['cluster_count']}; noise={metrics['noise_count']}"
            ), dict(metrics)

        m04 = _run_step(result, "M04", run_m04)
        if m04 is None:
            result["modules"]["M05"] = _module("not_run", "M04 prerequisite failed")
            result["modules"]["M06"] = _module("not_run", "M04 prerequisite failed")
        else:
            m05_dir = work_dir / "m05"

            def run_m05():
                value = modules["M05"].analyze_clusters(
                    m04_dir / "clusters.json", m05_dir, framing_json=m03_dir / "framing.json"
                )
                metrics = value["metrics"]
                return value, (
                    f"aligned={metrics['aligned_message_count']}; "
                    f"unaligned={metrics['unaligned_message_count']}; "
                    f"mean_identity={metrics['mean_identity_on_paired_bytes']}"
                ), dict(metrics)

            m05 = _run_step(result, "M05", run_m05)
            if m05 is None:
                result["modules"]["M06"] = _module("not_run", "M05 prerequisite failed")
            else:
                m06_dir = work_dir / "m06"

                def run_m06():
                    value = modules["M06"].analyze_alignments(
                        m05_dir / "alignments.json", m06_dir
                    )
                    metrics = value["metrics"]
                    return value, (
                        f"fields={metrics['field_candidate_count']}; "
                        f"boundaries={metrics['boundary_candidate_count']}; "
                        f"length_hypotheses={metrics['length_hypothesis_count']}"
                    ), dict(metrics)

                m06 = _run_step(result, "M06", run_m06)

    for name, reason in (
        ("M07", "no capture headers or dissector scope"),
        ("M08", "message corpus is not an encoded-content recovery fixture"),
        ("M09", "no packet timestamps or directions"),
        ("M10", "no flow features"),
        ("M11", "no behavior labels and leakage-safe collection groups"),
    ):
        result["modules"][name] = _module("not_applicable", reason)

    m12_inputs: dict[str, Path] = {}
    if m01 is not None:
        m12_inputs["M01"] = m01_dir / "result.json"
    if m02 is not None:
        m12_inputs["M02"] = m02_dir / "features.json"
    if m03 is not None:
        m12_inputs["M03"] = m03_dir / "framing.json"
    if m04 is not None:
        m12_inputs["M04"] = work_dir / "m04" / "clusters.json"
    if m05 is not None:
        m12_inputs["M05"] = work_dir / "m05" / "alignments.json"
    if m06 is not None:
        m12_inputs["M06"] = work_dir / "m06" / "format.json"
    m12_dir = work_dir / "m12"

    def run_m12():
        value = modules["M12"].build_report(m12_inputs, m12_dir)
        evidence = json.loads((m12_dir / "evidence.json").read_text(encoding="utf-8"))
        return value, f"evidence_records={len(evidence)}; report_status={value['status']}", {
            "evidence_count": len(evidence),
            "input_module_count": len(m12_inputs),
        }

    if m12_inputs:
        _run_step(result, "M12", run_m12)
    else:
        result["modules"]["M12"] = _module("not_run", "no upstream artifacts succeeded")
    return _finalize(result)


def _finalize(result: dict[str, Any]) -> dict[str, Any]:
    statuses = [item["status"] for item in result["modules"].values()]
    if "failed" in statuses:
        result["outcome"] = "completed_with_failures"
    elif any(
        status in {"not_applicable", "not_run", "partial", "unknown", "empty", "insufficient_metadata", "insufficient_evidence"}
        for status in statuses
    ):
        result["outcome"] = "completed_with_limits"
    else:
        result["outcome"] = "completed"
    return result


def render_sample_report(result: dict[str, Any], *, generated_at: str) -> str:
    lines = [
        f"# {result['artifact_id']} 测试报告",
        "",
        f"生成日期：{generated_at}",
        "",
        "## 输入",
        "",
        "| 字段 | 值 |",
        "|---|---|",
        f"| 数据集 | `{result['dataset_id']}` |",
        f"| 标称协议/类型 | {result['protocol']} |",
        f"| 路径 | `{result['input_path']}` |",
        f"| 大小 | {result['input_size']} bytes |",
        f"| SHA-256 | `{result['input_sha256']}` |",
        f"| 总体结果 | `{result['outcome']}` |",
        "",
        "## 模块结果",
        "",
        "| 模块 | 状态 | 结果摘要 |",
        "|---|---|---|",
    ]
    for name in sorted(result["modules"]):
        item = result["modules"][name]
        detail = str(item["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {name} | `{item['status']}` | {detail} |")
    lines.extend(["", "## 主要观测", ""])
    if result["highlights"]:
        lines.extend(f"- {item}" for item in result["highlights"])
    else:
        lines.append("- 未获得超出模块状态和指标的强证据。")
    lines.extend(["", "## 限制", ""])
    if result["limitations"]:
        lines.extend(f"- {item}" for item in result["limitations"])
    else:
        lines.append("- 未记录额外限制；仍不得把统计相关性当成协议语义真值。")
    lines.extend(
        [
            "",
            "## 结论",
            "",
            "本报告只陈述当前模块从该固定输入得到的可复现结果。"
            "协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。"
            "M10 模式不是应用标签，M11 未运行时不得推断行为类别。",
            "",
        ]
    )
    return "\n".join(lines)


def render_overall_report(results: list[dict[str, Any]], *, generated_at: str) -> str:
    outcomes = Counter(item["outcome"] for item in results)
    module_failures = Counter(
        name
        for result in results
        for name, item in result["modules"].items()
        if item["status"] == "failed"
    )
    lines = [
        "# 公共协议样例总体测试报告",
        "",
        f"生成日期：{generated_at}",
        "",
        "## 总览",
        "",
        f"本次共测试 {len(results)} 个固定输入。"
        f"完成 {outcomes.get('completed', 0)} 个，"
        f"带预期限制完成 {outcomes.get('completed_with_limits', 0)} 个，"
        f"带模块失败完成 {outcomes.get('completed_with_failures', 0)} 个。",
        "",
        "`not_applicable` 表示输入不具备模块所需元数据或真值，不计为运行失败。"
        "例如 Hex 消息集没有时间戳和方向，因此不能执行 M09；没有行为标签，因此不能执行 M11。",
        "",
        "## 样例矩阵",
        "",
        "| 样例 | 标称协议/类型 | 结果 | M01 | M03 | M07 | M09 | M10 | M12 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        status = lambda name: result["modules"].get(name, {}).get("status", "-")
        lines.append(
            f"| [{result['artifact_id']}]({result['artifact_id']}.md) | "
            f"{result['protocol']} | `{result['outcome']}` | `{status('M01')}` | "
            f"`{status('M03')}` | `{status('M07')}` | `{status('M09')}` | "
            f"`{status('M10')}` | `{status('M12')}` |"
        )
    lines.extend(["", "## 汇总结论", ""])
    if module_failures:
        lines.append(
            "- 出现模块失败："
            + ", ".join(f"{name}={count}" for name, count in sorted(module_failures.items()))
            + "。详见对应样例报告。"
        )
    else:
        lines.append("- 没有模块运行失败；所有非运行项均因输入前置条件不满足而明确标为 `not_applicable`。")
    capture_results = [item for item in results if item["modules"].get("M07")]
    protocol_evidence = [
        (item["artifact_id"], item["modules"]["M07"]["metrics"].get("protocols", []))
        for item in capture_results
        if item["modules"]["M07"]["metrics"].get("protocols")
    ]
    lines.append(
        f"- {len(protocol_evidence)} 个抓包产生了 M07 批准协议字段证据；"
        "其余抓包的来源协议标签不能替代本地识别证据。"
    )
    lines.append(
        "- BinaryInferno 消息通过派生 u32be 长度包装进入 M03～M06；"
        "该包装只用于可重复测试，不证明原协议包含同样的长度字段。"
    )
    lines.append(
        "- 本批数据没有可靠的行为类别、采集任务和泄漏安全分组，因此总体报告不提供 M11 准确率。"
    )
    lines.extend(["", "## M07 协议证据", ""])
    if protocol_evidence:
        for artifact_id, protocols in protocol_evidence:
            lines.append(f"- `{artifact_id}`：{', '.join(protocols)}")
    else:
        lines.append("- 未获得批准协议字段证据。")
    lines.extend(["", "## 安全与解释边界", ""])
    lines.extend(
        [
            "- ZeroAccess 和 Mirai 仅作离线分析，禁止回放、执行载荷或连接捕获地址。",
            "- 高熵、聚类、稳定字段和周期模式都不是加密、协议语义、应用身份或恶意性的单独证明。",
            "- 报告中的协议名称来自冻结清单；本地识别结论必须另外有 M07 批准字段证据。",
            "",
        ]
    )
    return "\n".join(lines)


def evaluate_all(
    manifest_path: Path,
    work_root: Path,
    report_root: Path,
    *,
    generated_at: str,
    tshark_path: Path | None = None,
    dataset_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    if work_root.exists():
        raise FileExistsError(f"work directory already exists: {work_root}")
    if report_root.exists():
        raise FileExistsError(f"report directory already exists: {report_root}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    external_root = manifest_path.parent
    work_root.mkdir(parents=True)
    report_root.mkdir(parents=True)
    modules = load_modules()
    results = []
    datasets = [item for item in manifest["datasets"] if dataset_ids is None or item["dataset_id"] in dataset_ids]
    if not datasets:
        raise ValueError("no datasets matched --dataset-id")
    for dataset in datasets:
        for artifact in dataset["files"]:
            input_path = external_root / artifact["path"]
            work_dir = work_root / artifact["artifact_id"]
            if artifact.get("observed_format"):
                result = evaluate_capture(
                    dataset, artifact, input_path, work_dir, modules,
                    tshark_path=tshark_path,
                )
            else:
                result = evaluate_hex_messages(dataset, artifact, input_path, work_dir, modules)
            results.append(result)
            (report_root / f"{artifact['artifact_id']}.md").write_text(
                render_sample_report(result, generated_at=generated_at), encoding="utf-8"
            )
    (report_root / "summary.json").write_text(
        json.dumps({"generated_at": generated_at, "results": results}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (report_root / "README.md").write_text(
        render_overall_report(results, generated_at=generated_at), encoding="utf-8"
    )
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate every frozen public protocol sample.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--report-root", type=Path, required=True)
    parser.add_argument("--generated-at", default=date.today().isoformat())
    parser.add_argument(
        "--tshark", type=Path,
        help="Path to tshark.exe when it is not available on PATH.",
    )
    parser.add_argument("--dataset-id", action="append", help="Evaluate only this frozen dataset id; may be repeated.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results = evaluate_all(
            args.manifest,
            args.work_root,
            args.report_root,
            generated_at=args.generated_at,
            tshark_path=args.tshark,
            dataset_ids=set(args.dataset_id) if args.dataset_id else None,
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"public-sample-evaluation: {exc}", file=sys.stderr)
        return 2
    failures = sum(item["outcome"] == "completed_with_failures" for item in results)
    print(args.report_root / "README.md")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

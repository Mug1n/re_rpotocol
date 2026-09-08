#!/usr/bin/env python3
"""M12 deterministic evidence normalization and Markdown reporting."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import load_json_artifact_with_sha256, sha256_file


SCHEMA_VERSION = "0.1"
EVIDENCE_SCHEMA = ROOT / "research" / "M12-llm" / "evidence.schema.json"
MANIFEST_SCHEMA = ROOT / "research" / "M12-llm" / "report-manifest.schema.json"
MODULE_SCHEMAS = {
    "M01": ROOT / "research" / "M01-input" / "input-artifact.schema.json",
    "M03": ROOT / "research" / "M03-framing" / "framing.schema.json",
    "M04": ROOT / "research" / "M04-clustering" / "clustering.schema.json",
    "M05": ROOT / "research" / "M05-alignment" / "alignment.schema.json",
    "M06": ROOT / "research" / "M06-fields" / "format.schema.json",
    "M07": ROOT / "research" / "M07-standard-protocols" / "protocols.schema.json",
    "M08": ROOT / "research" / "M08-recovery" / "recovery.schema.json",
    "M09": ROOT / "research" / "M09-flow-features" / "flow-features.schema.json",
    "M10": ROOT / "research" / "M10-behavior-analysis" / "behaviors.schema.json",
    "M11": ROOT / "research" / "M11-behavior-classification" / "classification.schema.json",
}
EXPECTED_MODULES = tuple(f"M{index:02d}" for index in range(1, 12))
ModelAdapter = Callable[[list[dict[str, Any]]], Any]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _evidence_id(module: str, record_id: str, observation: str) -> str:
    digest = hashlib.sha256(f"{module}\0{record_id}\0{observation}".encode("utf-8")).hexdigest()[:16]
    return f"evidence-{module.lower()}-{digest}"


def _resolve_reference(input_path: Path, reference: str) -> Path:
    path = Path(reference)
    if path.is_absolute():
        return path
    nearby = input_path.parent / path
    return nearby if nearby.is_file() else Path.cwd() / path


def _verify_upstream_reference(input_path: Path, artifact: dict[str, Any]) -> None:
    source = artifact.get("source")
    if not isinstance(source, dict):
        return
    reference = source.get("artifact_path")
    expected = source.get("artifact_sha256")
    if not isinstance(reference, str) or not isinstance(expected, str):
        return
    resolved = _resolve_reference(input_path, reference)
    if not resolved.is_file():
        raise FileNotFoundError(f"referenced upstream artifact does not exist: {resolved}")
    actual = sha256_file(resolved)
    if actual != expected:
        raise ValueError(f"upstream artifact SHA-256 mismatch: expected {expected}, got {actual}")


def _source_ref(context: dict[str, Any], record_id: str) -> dict[str, Any]:
    return {
        "module": context["module"],
        "artifact_path": str(context["path"]),
        "artifact_sha256": context["artifact_sha256"],
        "record_id": record_id,
        "schema_version": context["schema_version"],
    }


def _record(
    context: dict[str, Any],
    *,
    record_id: str,
    scope_type: str,
    scope_id: str,
    observation: str,
    method: str,
    limitations: list[str],
) -> dict[str, Any]:
    module = context["module"]
    return {
        "evidence_id": _evidence_id(module, record_id, observation),
        "module": module,
        "source_ref": _source_ref(context, record_id),
        "scope": {"type": scope_type, "id": scope_id},
        "observation": observation,
        "method": method,
        "limitations": limitations,
    }


def _adapt_m01(context: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    missing = sorted(key for key, value in artifact["metadata_availability"].items() if value is not True)
    limitations = list(artifact["warnings"])
    if missing:
        limitations.append("Unavailable or partial metadata: " + ", ".join(missing))
    observation = f"Input format={artifact['format']}, status={artifact['status']}, length={artifact['length']} bytes."
    return [_record(context, record_id=artifact["id"], scope_type="input", scope_id=artifact["id"], observation=observation, method="M01 validated input artifact", limitations=limitations)]


def _adapt_m07(context: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in artifact["observations"]:
        fields = ", ".join(f"{field['field']}={field['value']}" for field in item["field_evidence"])
        observation = f"Protocol {item['protocol']} observed with visibility={item['visibility']}; {fields}."
        records.append(_record(context, record_id=item["observation_id"], scope_type=item["scope_type"], scope_id=item["scope_id"], observation=observation, method=item["recognition_mode"], limitations=list(item["limitations"])))
    for item in artifact["unknown_scopes"]:
        observation = f"Protocol could not be determined: {item['reason_code']}."
        records.append(_record(context, record_id=f"unknown-{item['scope_id']}-{item['reason_code']}", scope_type=item["scope_type"], scope_id=item["scope_id"], observation=observation, method="M07 explicit degradation", limitations=[item["reason_code"]]))
    return records


def _adapt_m08(context: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in artifact["recoveries"]:
        operations = " -> ".join(step["operation"] for step in item["transformation_chain"])
        observation = f"Recovered {item['output']['length']} bytes via {operations}; completeness={item['completeness']}."
        records.append(_record(context, record_id=item["recovery_id"], scope_type="byte_range", scope_id=item["recovery_id"], observation=observation, method=item["basis"], limitations=list(item["evidence"])))
    for item in artifact["skipped_sources"]:
        observation = f"Content recovery skipped: {item['reason_code']}."
        records.append(_record(context, record_id=f"skip-{item['reason_code']}", scope_type="source", scope_id=item["source_ref"]["record_id"], observation=observation, method="M08 explicit degradation", limitations=[item["detail"]]))
    return records


def _adapt_generic(context: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    module = context["module"]
    status = str(artifact.get("status", "unknown"))
    warnings = [str(item) for item in artifact.get("warnings", [])]
    observation = f"{module} artifact status={status}."
    record_id = str(artifact.get("id") or artifact.get("source", {}).get("record_id") or context["path"].name)
    return [_record(context, record_id=record_id, scope_type="artifact", scope_id=record_id, observation=observation, method=f"{module} validated artifact adapter", limitations=warnings)]


def _normalize(context: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    module = context["module"]
    if module == "M01":
        return _adapt_m01(context, artifact)
    if module == "M07":
        return _adapt_m07(context, artifact)
    if module == "M08":
        return _adapt_m08(context, artifact)
    return _adapt_generic(context, artifact)


def _render_report(evidence: list[dict[str, Any]], missing_modules: list[str], model_claims: list[dict[str, Any]]) -> tuple[str, dict[str, list[str]]]:
    facts = [f"- [{item['evidence_id']}] {item['observation']}" for item in evidence]
    hypotheses = [f"- [模型生成；依据 {', '.join(item['evidence_ids'])}] {item['text']}" for item in model_claims]
    unable: list[str] = []
    unable_ids: list[str] = []
    if missing_modules:
        unable.append("- 未提供以下模块的经校验证据：" + "、".join(missing_modules) + "。")
    for item in evidence:
        for limitation in item["limitations"]:
            unable.append(f"- [{item['evidence_id']}] {limitation}")
            unable_ids.append(item["evidence_id"])
    suggestions = ["- 获取缺失模块的合法 artifact 后重新生成报告。"] if missing_modules else ["- 结合当前限制审阅证据，再决定是否追加人工或模型解释。"]
    report = "\n".join([
        "# 协议与流量分析报告", "", "## 观测事实", "", *(facts or ["- 没有可呈现的观测事实。"]), "",
        "## 解释与假设", "", *(hypotheses or ["- 未生成解释假设；确定性证据保持权威。"]), "",
        "## 无法判断", "", *(unable or ["- 当前输入未声明额外的不可判断项。"]), "",
        "## 后续建议", "", *suggestions, "",
    ])
    sections = {
        "observed_facts": [item["evidence_id"] for item in evidence],
        "interpretations": sorted({value for claim in model_claims for value in claim["evidence_ids"]}),
        "undetermined": sorted(set(unable_ids)),
        "recommendations": [],
    }
    return report, sections


def build_report(inputs: Mapping[str, str | Path], output_dir: str | Path, *, max_evidence: int = 500, model_adapter: ModelAdapter | None = None) -> dict[str, Any]:
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    if max_evidence <= 0:
        raise ValueError("max_evidence must be positive")
    normalized_inputs = {str(module).upper(): Path(path) for module, path in inputs.items()}
    if not normalized_inputs:
        raise ValueError("at least one input artifact is required")
    evidence: list[dict[str, Any]] = []
    manifest_inputs: list[dict[str, Any]] = []
    for module in sorted(normalized_inputs):
        path = normalized_inputs[module]
        schema_path = MODULE_SCHEMAS.get(module)
        if schema_path is None or not schema_path.is_file():
            raise ValueError(f"no installed schema for module {module}")
        artifact, artifact_sha = load_json_artifact_with_sha256(path)
        jsonschema.validate(artifact, json.loads(schema_path.read_text(encoding="utf-8")))
        _verify_upstream_reference(path, artifact)
        context = {"module": module, "path": path, "artifact_sha256": artifact_sha, "schema_version": str(artifact.get("schema_version", "unknown"))}
        manifest_inputs.append({"module": module, "artifact_path": str(path), "artifact_sha256": artifact_sha, "schema_version": str(artifact.get("schema_version", "unknown")), "status": str(artifact.get("status", "unknown"))})
        evidence.extend(_normalize(context, artifact))
    deduplicated = {_canonical(item): item for item in evidence}
    all_evidence = sorted(deduplicated.values(), key=lambda item: item["evidence_id"])
    included = all_evidence[:max_evidence]
    omitted = len(all_evidence) - len(included)
    evidence_schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
    for item in included:
        jsonschema.validate(item, evidence_schema)

    warnings: list[str] = []
    if omitted:
        warnings.append(f"Evidence truncated deterministically: omitted {omitted} records.")
    model_claims: list[dict[str, Any]] = []
    if model_adapter is not None:
        try:
            candidate = model_adapter(included)
            valid_ids = {item["evidence_id"] for item in included}
            if not isinstance(candidate, list):
                raise ValueError("model response root must be a list")
            for claim in candidate:
                if not isinstance(claim, dict) or not isinstance(claim.get("text"), str) or not claim["text"].strip():
                    raise ValueError("model claim is malformed")
                references = claim.get("evidence_ids")
                if not isinstance(references, list) or not references or any(item not in valid_ids for item in references):
                    raise ValueError("model claim contains an unsupported evidence reference")
                model_claims.append({"text": claim["text"].strip(), "evidence_ids": sorted(set(references))})
        except Exception as exc:
            warnings.append(f"Model explanation skipped: {type(exc).__name__}: {exc}")
            model_claims = []
    missing_modules = sorted(set(EXPECTED_MODULES) - set(normalized_inputs))
    report, sections = _render_report(included, missing_modules, model_claims)
    report_bytes = report.encode("utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete" if not missing_modules else "partial",
        "inputs": manifest_inputs,
        "generation_mode": "deterministic_with_model" if model_claims else "deterministic",
        "sections": sections,
        "truncation": {"limit": max_evidence, "included": len(included), "omitted": omitted},
        "warnings": warnings,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    jsonschema.validate(manifest, json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (staging / "report.md").write_bytes(report_bytes)
        (staging / "evidence.json").write_text(json.dumps(included, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (staging / "report_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a deterministic evidence report from validated module artifacts.")
    parser.add_argument("--input", action="append", required=True, metavar="MODULE=PATH")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-evidence", type=int, default=500)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inputs: dict[str, Path] = {}
    try:
        for value in args.input:
            module, separator, path = value.partition("=")
            if not separator or not module or not path:
                raise ValueError("each --input must use MODULE=PATH")
            if module.upper() in inputs:
                raise ValueError(f"duplicate module input: {module.upper()}")
            inputs[module.upper()] = Path(path)
        build_report(inputs, args.output_dir, max_evidence=args.max_evidence)
    except (FileNotFoundError, FileExistsError, ValueError, jsonschema.ValidationError) as exc:
        print(f"m12: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

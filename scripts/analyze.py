#!/usr/bin/env python3
"""Run the versioned single-input analysis graph and publish a hash-bound manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.artifact_contracts import validate_m01_references
from experiments.M01.run import analyze_input
from experiments.M02.run import analyze_file as analyze_features
from experiments.M03.run import analyze_file as analyze_framing
from experiments.M04.run import analyze_framing as analyze_clusters
from experiments.M05.run import analyze_clusters as analyze_alignments
from experiments.M06.run import analyze_alignments as analyze_fields
from experiments.M07.run import analyze_protocols
from experiments.M08.run import analyze_payload_source, analyze_recovery
from experiments.M09.run import analyze as analyze_flow_features
from experiments.M10.run import analyze as analyze_behaviors
from experiments.M11.build_rows import build as build_m11_rows
from experiments.M12.deepseek_adapter import invoke as invoke_deepseek
from experiments.M12.run import build_report
from experiments.payload_sources import extract_payload_sources
from scripts.predict_acceptance_classifier import predict as predict_c2

PROFILE_SCHEMA = ROOT / "research" / "analysis-profile.schema.json"
RUN_SCHEMA = ROOT / "research" / "run-manifest.schema.json"
M01_SCHEMA = ROOT / "research" / "M01-input" / "input-artifact.schema.json"
SCHEMA_VERSION = "0.1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def _resolve_profile_path(profile_path: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    from_cwd = Path.cwd() / candidate
    return from_cwd if from_cwd.exists() else profile_path.parent / candidate


def _tool_record(tshark: Path | None) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(tshark) if tshark else None, "available": False, "version": None}
    if tshark is None or not tshark.is_file():
        return result
    completed = subprocess.run(
        [str(tshark), "--version"], capture_output=True, text=True, timeout=10, check=False
    )
    result["available"] = completed.returncode == 0
    if result["available"]:
        result["version"] = (completed.stdout.splitlines() or [""])[0]
    return result


def _load_profile(path: Path) -> dict[str, Any]:
    profile = _load_json(path)
    jsonschema.validate(profile, _load_json(PROFILE_SCHEMA))
    stages = set(profile["stages"])
    dependencies = {
        "PAYLOAD_SOURCES": {"M01"}, "M04": {"M03"}, "M05": {"M04"},
        "M06": {"M05"}, "M07": {"M01"}, "M09": {"M01"},
        "M10": {"M09"}, "M11": {"M09"},
    }
    for stage, required in dependencies.items():
        if stage in stages and not required <= stages:
            raise ValueError(f"profile stage {stage} requires {', '.join(sorted(required))}")
    if "M03" in stages and "structure" not in profile:
        raise ValueError("profile stage M03 requires a structure configuration")
    if profile.get("structure", {}).get("source") == "first_http_body" and "PAYLOAD_SOURCES" not in stages:
        raise ValueError("first_http_body structure requires PAYLOAD_SOURCES")
    return profile


def _record(path: Path, *, module: str, instance_id: str, status: str,
            scope: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact does not exist: {path}")
    return {
        "module": module, "instance_id": instance_id, "path": str(path),
        "sha256": _sha256(path), "length": path.stat().st_size,
        "schema_version": str(_load_json(path).get("schema_version", "unknown")),
        "status": status, "scope": scope or {},
    }


def _validate_reused_m01(input_path: Path, artifact_path: Path) -> dict[str, Any]:
    artifact = _load_json(artifact_path)
    jsonschema.validate(artifact, _load_json(M01_SCHEMA))
    validate_m01_references(artifact)
    if artifact["sha256"] != _sha256(input_path) or artifact["length"] != input_path.stat().st_size:
        raise ValueError("reused M01 artifact does not describe the supplied input bytes")
    return artifact


def run_pipeline(
    input_path: str | Path,
    output_dir: str | Path,
    profile_path: str | Path,
    *,
    tshark_path: str | Path | None = None,
    invoke_model: bool = False,
) -> dict[str, Any]:
    source, destination, profile_file = Path(input_path), Path(output_dir), Path(profile_path)
    failure_path = destination.parent / f"{destination.name}.failure.json"
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    if not source.is_file():
        raise FileNotFoundError(f"input does not exist or is not a file: {source}")
    if not profile_file.is_file():
        raise FileNotFoundError(f"profile does not exist: {profile_file}")
    if failure_path.exists():
        raise FileExistsError(f"failure record already exists: {failure_path}")

    profile_data = _load_profile(profile_file)
    selected = set(profile_data["stages"])
    tshark = Path(tshark_path) if tshark_path else None
    started_at, started_clock = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    stage_records: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    module_inputs: dict[str, list[Path]] = {}
    payload_manifest: dict[str, Any] | None = None
    payload_manifest_path: Path | None = None

    def add(module: str, instance_id: str, path: Path, result: dict[str, Any],
            scope: dict[str, Any] | None = None) -> None:
        artifacts.append(_record(path, module=module, instance_id=instance_id,
                                 status=str(result.get("status", "unknown")), scope=scope))
        if len(module) == 3 and module.startswith("M") and module[1:].isdigit() and module != "M12":
            module_inputs.setdefault(module, []).append(path)

    def execute(name: str, action: Callable[[], Any], *, reused: bool = False) -> Any:
        began = time.perf_counter()
        try:
            value = action()
        except Exception as exc:
            stage_records.append({"stage": name, "status": "failed",
                                  "elapsed_seconds": round(time.perf_counter() - began, 6),
                                  "reason": f"{type(exc).__name__}: {exc}"})
            raise
        stage_records.append({"stage": name, "status": "reused_verified" if reused else "completed",
                              "elapsed_seconds": round(time.perf_counter() - began, 6), "reason": None})
        return value

    destination.mkdir(parents=True)
    try:
        reuse = profile_data.get("reuse", {})
        if "M01" in selected:
            if "m01" in reuse:
                m01_path = _resolve_profile_path(profile_file, reuse["m01"])
                m01 = execute("M01", lambda: _validate_reused_m01(source, m01_path), reused=True)
            else:
                m01_path = destination / "m01" / "result.json"
                m01 = execute("M01", lambda: analyze_input(
                    source, m01_path.parent, tshark_path=tshark,
                    capinfos_path=(tshark.parent / "capinfos.exe") if tshark else None))
            add("M01", "input", m01_path, m01, {"input_sha256": _sha256(source)})
        else:
            m01_path = None

        if "M02" in selected:
            m02_path = destination / "m02" / "features.json"
            m02 = execute("M02", lambda: analyze_features(source, m02_path.parent, **profile_data.get("m02", {})))
            add("M02", "input", m02_path, m02)

        if "M07" in selected:
            assert m01_path is not None
            if "m07" in reuse:
                m07_path = _resolve_profile_path(profile_file, reuse["m07"])
                m07 = execute("M07", lambda: _load_json(m07_path), reused=True)
            else:
                m07_path = destination / "m07" / "protocols.json"
                m07 = execute("M07", lambda: analyze_protocols(
                    m01_path, m07_path.parent, tshark_path=tshark, **profile_data.get("m07", {})))
            add("M07", "input", m07_path, m07)

        if "PAYLOAD_SOURCES" in selected:
            assert m01_path is not None
            payload_manifest_path = destination / "payloads" / "payload_sources.json"
            payload_manifest = execute("PAYLOAD_SOURCES", lambda: extract_payload_sources(
                m01_path, payload_manifest_path.parent))
            add("PAYLOAD_SOURCES", "http", payload_manifest_path, payload_manifest)

        if "M08" in selected:
            def recover_all() -> list[tuple[Path, dict[str, Any], dict[str, Any]]]:
                recovered: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
                if payload_manifest and payload_manifest_path and payload_manifest.get("sources"):
                    for index, item in enumerate(payload_manifest["sources"]):
                        target = destination / "m08" / f"{index:04d}"
                        result = analyze_payload_source(payload_manifest_path, item["source_id"], target)
                        recovered.append((target / "recovery.json", result, {
                            "source_id": item["source_id"], "stream_id": item["stream_id"],
                            "direction": item["direction"]}))
                else:
                    target = destination / "m08" / "direct"
                    result = analyze_recovery(source, target)
                    recovered.append((target / "recovery.json", result, {"source": "direct_input"}))
                return recovered

            for index, (path, result, scope) in enumerate(execute("M08", recover_all)):
                add("M08", f"recovery-{index:04d}", path, result, scope)

        if "M03" in selected:
            structure = profile_data["structure"]
            structure_source = source
            if structure["source"] == "first_http_body":
                if not payload_manifest or not payload_manifest.get("sources") or payload_manifest_path is None:
                    raise ValueError("no HTTP body is available for the configured structure stage")
                first = payload_manifest["sources"][0]
                structure_source = payload_manifest_path.parent / first["output"]["artifact_ref"]
            parameters = dict(structure["parameters"])
            if parameters.get("frame_size") == "source_length":
                parameters["frame_size"] = structure_source.stat().st_size
            m03_path = destination / "m03" / "framing.json"
            m03 = execute("M03", lambda: analyze_framing(
                structure_source, m03_path.parent, rule=structure["rule"], parameters=parameters))
            add("M03", "structure", m03_path, m03,
                {"rule_origin": structure["rule_origin"], "source": structure["source"]})

        if "M04" in selected:
            m04_path = destination / "m04" / "clusters.json"
            m04 = execute("M04", lambda: analyze_clusters(m03_path, m04_path.parent, **profile_data.get("m04", {})))
            add("M04", "structure", m04_path, m04)

        if "M05" in selected:
            m05_path = destination / "m05" / "alignments.json"
            m05 = execute("M05", lambda: analyze_alignments(m04_path, m05_path.parent))
            add("M05", "structure", m05_path, m05)

        if "M06" in selected:
            m06_path = destination / "m06" / "format.json"
            m06 = execute("M06", lambda: analyze_fields(m05_path, m06_path.parent))
            add("M06", "structure", m06_path, m06)

        if "M09" in selected:
            assert m01_path is not None
            m09_path = destination / "m09" / "flow_features.json"
            m09 = execute("M09", lambda: analyze_flow_features(m01_path, m09_path.parent))
            add("M09", "flows", m09_path, m09)

        if "M10" in selected:
            m10_path = destination / "m10" / "behaviors.json"
            m10 = execute("M10", lambda: analyze_behaviors(m09_path, m10_path.parent))
            add("M10", "flows", m10_path, m10)

        if "M11" in selected:
            if "m11" not in reuse:
                stage_records.append({"stage": "M11", "status": "blocked", "elapsed_seconds": 0.0,
                                      "reason": "profile has no verified reusable M11 training artifact"})
            else:
                m11_path = _resolve_profile_path(profile_file, reuse["m11"])
                m11 = execute("M11", lambda: _load_json(m11_path), reused=True)
                add("M11", "trained-classifier", m11_path, m11)
                classifier = profile_data.get("classifier")
                if classifier:
                    rows_path = destination / "m11" / "prediction-rows.json"
                    prediction_path = destination / "m11" / "prediction.json"
                    evaluation = _resolve_profile_path(profile_file, classifier["evaluation"])

                    def run_prediction() -> dict[str, Any]:
                        build_m11_rows(m09_path, rows_path)
                        return predict_c2(evaluation, rows_path, prediction_path)

                    prediction = execute("M11_PREDICTION", run_prediction)
                    add("M11_PREDICTION", "new-input", prediction_path, prediction)

        if "M12" in selected:
            m12_inputs: dict[str, Path | list[Path]] = {
                module: paths[0] if len(paths) == 1 else paths for module, paths in module_inputs.items()
            }
            m12_path = destination / "m12" / "report_manifest.json"
            m12 = execute("M12", lambda: build_report(m12_inputs, m12_path.parent, **profile_data.get("m12", {})))
            add("M12", "report", m12_path, m12)

        model: dict[str, Any] = {"status": "not_requested"}
        if invoke_model:
            key = os.environ.get("DEEPSEEK_API_KEY", "")
            if not key:
                model = {"status": "blocked", "reason": "DEEPSEEK_API_KEY was not supplied to this process."}
            elif "M12" not in selected:
                model = {"status": "blocked", "reason": "M12 evidence is required before model invocation."}
            else:
                evidence = json.loads((destination / "m12" / "evidence.json").read_text(encoding="utf-8"))
                model = execute("MODEL", lambda: invoke_deepseek(
                    evidence, destination / "model", key,
                    str(profile_data.get("model", {}).get("name", "deepseek-v4-flash"))))

        blocking = [item for item in stage_records if item["status"] in {"failed", "blocked"}]
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": f"run-{_sha256(source)[:12]}-{profile_data['profile_id']}",
            "status": "partial" if blocking else "complete",
            "started_at": started_at, "elapsed_seconds": round(time.perf_counter() - started_clock, 6),
            "input": {"path": str(source), "sha256": _sha256(source), "length": source.stat().st_size},
            "profile": {"path": str(profile_file), "sha256": _sha256(profile_file),
                        "profile_id": profile_data["profile_id"], "schema_version": profile_data["schema_version"]},
            "environment": {"python": platform.python_version(), "platform": platform.platform(),
                            "tshark": _tool_record(tshark)},
            "stages": stage_records, "artifacts": artifacts, "model": model,
            "limitations": list(profile_data.get("limitations", [])),
        }
        jsonschema.validate(manifest, _load_json(RUN_SCHEMA))
        _write_json(destination / "run_manifest.json", manifest)
        return manifest
    except Exception as exc:
        failure = {
            "schema_version": SCHEMA_VERSION, "status": "failed", "started_at": started_at,
            "elapsed_seconds": round(time.perf_counter() - started_clock, 6),
            "input": {"path": str(source), "sha256": _sha256(source), "length": source.stat().st_size},
            "profile": {"path": str(profile_file), "sha256": _sha256(profile_file)},
            "stages": stage_records, "error": {"type": type(exc).__name__, "message": str(exc)},
        }
        shutil.rmtree(destination, ignore_errors=True)
        _write_json(failure_path, failure)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the single-input, profile-driven DAT analysis pipeline.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--invoke-model", action="store_true",
                        help="Explicitly invoke DeepSeek using DEEPSEEK_API_KEY; never enabled by default.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_pipeline(args.input, args.output_dir, args.profile,
                     tshark_path=args.tshark, invoke_model=args.invoke_model)
    except (KeyError, OSError, ValueError, RuntimeError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        print(f"analyze: {exc}", file=sys.stderr)
        return 2
    print(args.output_dir / "run_manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

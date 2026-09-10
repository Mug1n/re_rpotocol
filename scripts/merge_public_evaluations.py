#!/usr/bin/env python3
"""Merge independently rerun public-evaluation batches with manifest checks."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_renderer():
    path = ROOT / "scripts" / "evaluate_public_samples.py"
    spec = importlib.util.spec_from_file_location("public_evaluation_renderer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "data" / "external" / "test-samples-manifest.json")
    parser.add_argument("--report-root", required=True, type=Path)
    parser.add_argument("--input-summary", action="append", required=True, type=Path)
    parser.add_argument("--generated-at", required=True)
    args = parser.parse_args()
    if args.report_root.exists():
        raise FileExistsError(args.report_root)
    expected = {file["artifact_id"]: file for dataset in json.loads(args.manifest.read_text(encoding="utf-8"))["datasets"] for file in dataset["files"]}
    results = []
    for summary in args.input_summary:
        data = json.loads(summary.read_text(encoding="utf-8"))
        results.extend(data.get("results", []))
    actual = {item.get("artifact_id"): item for item in results}
    if len(actual) != len(results) or set(actual) != set(expected):
        raise ValueError("merged summaries do not cover exactly the frozen public manifest")
    for artifact_id, item in actual.items():
        if item.get("input_sha256") != expected[artifact_id]["sha256"] or item.get("input_size") != expected[artifact_id]["byte_size"]:
            raise ValueError(f"public result does not match frozen input: {artifact_id}")
    ordered = [actual[key] for key in sorted(actual)]
    renderer = load_renderer()
    args.report_root.mkdir(parents=True)
    copied: set[str] = set()
    for summary in args.input_summary:
        for report in summary.parent.glob("*.md"):
            if report.name == "README.md":
                continue
            if report.name in copied:
                raise ValueError(f"duplicate sample report: {report.name}")
            shutil.copyfile(report, args.report_root / report.name)
            copied.add(report.name)
    if copied != {f"{artifact_id}.md" for artifact_id in expected}:
        raise ValueError("merged sample report files do not cover the frozen public manifest")
    (args.report_root / "summary.json").write_text(json.dumps({"generated_at": args.generated_at, "results": ordered}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.report_root / "README.md").write_text(renderer.render_overall_report(ordered, generated_at=args.generated_at), encoding="utf-8")
    print(args.report_root / "README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

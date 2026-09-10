#!/usr/bin/env python3
"""Compose C's complete acceptance manifest without re-calling the model."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path: Path, **extra: object) -> dict:
    return {"path": str(path), "sha256": sha256(path), "length": path.stat().st_size, **extra}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--m12-manifest", required=True, type=Path)
    parser.add_argument("--base-run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    m12 = json.loads(args.m12_manifest.read_text(encoding="utf-8"))
    base = json.loads(args.base_run.read_text(encoding="utf-8"))
    inputs = {}
    for item in m12.get("inputs", []):
        path = Path(item["artifact_path"])
        inputs[item["module"]] = record(path, schema_version=item["schema_version"], status=item["status"])
    result = {
        "schema_version": "0.1", "status": "complete" if m12.get("status") == "complete" and base.get("model", {}).get("status") == "invoked" else "partial",
        "input": inputs,
        "deterministic_report": {"manifest": record(args.m12_manifest), "status": m12["status"], "generation_mode": m12["generation_mode"]},
        "recovery": base["recovery"], "classification": base["classification"], "model": base["model"],
        "limitations": list(base.get("limitations", [])) + ["Module statuses may still record honest partial or empty observations; complete means all M01--M11 artifact contracts were supplied."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

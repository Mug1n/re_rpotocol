#!/usr/bin/env python3
"""Attach and independently validate a persisted bounded-model response."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-manifest", required=True, type=Path)
    parser.add_argument("--model-dir", required=True, type=Path)
    args = parser.parse_args()
    run = json.loads(args.run_manifest.read_text(encoding="utf-8"))
    evidence_path = Path(run["deterministic_report"]["manifest"]["path"]).parent / "evidence.json"
    allowed = {item["evidence_id"] for item in json.loads(evidence_path.read_text(encoding="utf-8"))}
    manifest_path = args.model_dir / "model_manifest.json"
    model = json.loads(manifest_path.read_text(encoding="utf-8"))
    if model.get("status") != "invoked":
        raise ValueError("model was not invoked")
    for key, filename in (("request", "request.json"), ("response", "response.json")):
        path = args.model_dir / filename
        if not path.is_file() or sha256(path) != model[key]["sha256"]:
            raise ValueError(f"{key} artifact hash mismatch")
        model[key]["path"] = str(path)
    for claim in model.get("claims", []):
        if not claim.get("evidence_ids") or any(value not in allowed for value in claim["evidence_ids"]):
            raise ValueError("model claim cites evidence outside the deterministic report")
    manifest_path.write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run["model"] = {**model, "manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)}}
    run["status"] = "partial" if run["deterministic_report"]["status"] != "complete" else "complete"
    args.run_manifest.write_text(json.dumps(run, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.run_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

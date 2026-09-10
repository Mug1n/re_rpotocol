#!/usr/bin/env python3
"""Independently verify an acceptance integration manifest.

Exit 0 means all required gates, including a real semantic-model invocation,
passed.  Exit 3 means deterministic gates passed but model acceptance remains
blocked; it is deliberately not a success exit code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_record(item: dict) -> None:
    path = Path(item["path"])
    if not path.is_file():
        raise ValueError(f"missing artifact: {path}")
    if path.stat().st_size != item["length"] or sha256(path) != item["sha256"]:
        raise ValueError(f"artifact hash or length mismatch: {path}")


def verify_model(manifest: dict, deterministic: dict) -> None:
    model = manifest.get("model", {})
    if model.get("status") != "invoked":
        return
    pointer = model.get("manifest", {})
    path = Path(pointer.get("path", ""))
    if not path.is_file() or sha256(path) != pointer.get("sha256"):
        raise ValueError("model manifest hash mismatch")
    persisted = json.loads(path.read_text(encoding="utf-8"))
    if persisted.get("status") != "invoked" or persisted.get("model") != model.get("model"):
        raise ValueError("model invocation manifest is inconsistent")
    for key in ("request", "response"):
        item = persisted.get(key, {})
        artifact = Path(item.get("path", ""))
        if not artifact.is_file() or sha256(artifact) != item.get("sha256"):
            raise ValueError(f"model {key} hash mismatch")
    request = json.loads(Path(persisted["request"]["path"]).read_text(encoding="utf-8"))
    if request.get("key_persisted") is not False or request.get("model") != model.get("model"):
        raise ValueError("model request provenance is invalid")
    response = json.loads(Path(persisted["response"]["path"]).read_text(encoding="utf-8"))
    content = response.get("choices", [{}])[0].get("message", {}).get("content")
    try:
        raw_claims = json.loads(content).get("claims")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("model response is not JSON claims") from exc
    if raw_claims != persisted.get("claims") or raw_claims != model.get("claims"):
        raise ValueError("model claims do not match the recorded raw response")
    evidence_path = Path(deterministic["manifest"]["path"]).parent / "evidence.json"
    allowed = {item["evidence_id"] for item in json.loads(evidence_path.read_text(encoding="utf-8"))}
    if not raw_claims or any(not claim.get("text") or not claim.get("evidence_ids")
                             or any(item not in allowed for item in claim["evidence_ids"])
                             for claim in raw_claims):
        raise ValueError("model claims have missing or out-of-scope evidence citations")


def verify(manifest_path: Path) -> tuple[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("schema_version") != "0.1":
        raise ValueError("unsupported manifest schema")
    for item in manifest["input"].values():
        verify_record(item)
    deterministic = manifest["deterministic_report"]
    verify_record(deterministic["manifest"])
    if deterministic.get("generation_mode") != "deterministic":
        raise ValueError("unexpected unvalidated model generation mode")
    verify_model(manifest, deterministic)
    recovery = manifest["recovery"]
    if recovery.get("status") != "matched":
        raise ValueError("recovery truth gate did not match")
    verify_record(recovery["recovered"])
    verify_record(recovery["truth"])
    if recovery["recovered"]["sha256"] != recovery.get("expected_sha256"):
        raise ValueError("recovered bytes do not match independent truth hash")
    classifier = manifest["classification"]
    for key in ("evaluation", "prediction", "model"):
        verify_record(classifier[key])
    prediction = json.loads(Path(classifier["prediction"]["path"]).read_text(encoding="utf-8"))
    if prediction.get("model", {}).get("sha256") != classifier["model"]["sha256"]:
        raise ValueError("prediction is not bound to verified classifier model")
    if not prediction.get("predictions"):
        raise ValueError("prediction set is empty")
    return str(manifest.get("status", "missing")), str(manifest.get("model", {}).get("status", "missing"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify deterministic and semantic-model acceptance gates.")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        run_status, model_status = verify(args.manifest)
    except (KeyError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"acceptance: FAIL: {exc}")
        return 2
    if model_status != "invoked":
        print(f"acceptance: BLOCKED: semantic model status={model_status}")
        return 3
    if run_status != "complete":
        print(f"acceptance: PARTIAL: deterministic module coverage status={run_status}")
        return 3
    print("acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

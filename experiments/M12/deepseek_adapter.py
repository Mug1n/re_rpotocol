"""Bounded, auditable DeepSeek evidence-summary adapter.

The API key is accepted only as an in-memory argument.  Persisted request
artifacts intentionally omit it; model text cannot become an accepted claim
unless every cited evidence ID is from the supplied deterministic evidence.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API_URL = "https://api.deepseek.com/chat/completions"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def invoke(evidence: list[dict[str, Any]], output_dir: Path, api_key: str,
           model: str = "deepseek-v4-flash") -> dict[str, Any]:
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY is required")
    if output_dir.exists():
        raise FileExistsError(output_dir)
    compact = [{"evidence_id": item["evidence_id"], "observation": item["observation"],
                "limitations": item["limitations"]} for item in evidence]
    allowed = {item["evidence_id"] for item in compact}
    prompt = {
        "role": "user",
        "content": (
            "Summarize only the supplied deterministic network-analysis evidence. "
            "Return JSON only: {\"claims\":[{\"text\":string,\"evidence_ids\":[string]}]}. "
            "At most two claims. Each claim must cite one or more exact evidence_ids. "
            "Do not assert protocol semantics, ground truth, causality, or anything not entailed by observations.\n"
            + json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
        ),
    }
    request_body = {"model": model, "messages": [
        {"role": "system", "content": "You are a constrained evidence summarizer. Output valid JSON only."}, prompt],
        "temperature": 0, "max_tokens": 400, "stream": False,
        "thinking": {"type": "disabled"},
        "response_format": {"type": "json_object"}}
    encoded = json.dumps(request_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(API_URL, data=encoded, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(f"DeepSeek HTTP {exc.code}: {raw[:500].decode('utf-8', 'replace')}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"DeepSeek network error: {exc.reason}") from exc
    if status != 200:
        raise RuntimeError(f"DeepSeek unexpected HTTP status {status}")
    response_body = json.loads(raw.decode("utf-8"))
    content = response_body.get("choices", [{}])[0].get("message", {}).get("content")
    if not isinstance(content, str):
        raise ValueError("DeepSeek response has no message content")
    parsed = json.loads(content)
    claims = parsed.get("claims")
    if not isinstance(claims, list) or len(claims) > 2:
        raise ValueError("model response has an invalid claim list")
    for claim in claims:
        ids = claim.get("evidence_ids") if isinstance(claim, dict) else None
        if (not isinstance(claim.get("text"), str) or not claim["text"].strip()
                or not isinstance(ids, list) or not ids or any(value not in allowed for value in ids)):
            raise ValueError("model response contains an uncited or invalid claim")
    output_dir.mkdir(parents=True)
    request_record = {"api_url": API_URL, "model": model, "body": request_body,
                      "body_sha256": _sha(encoded), "key_persisted": False}
    (output_dir / "request.json").write_text(json.dumps(request_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "response.json").write_text(json.dumps(response_body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = {"status": "invoked", "model": model, "request": {"path": str(output_dir / "request.json"), "sha256": _sha((output_dir / "request.json").read_bytes())},
              "response": {"path": str(output_dir / "response.json"), "sha256": _sha((output_dir / "response.json").read_bytes())},
              "claims": claims, "usage": response_body.get("usage"), "limitations": ["Model claims are bounded to cited deterministic evidence."]}
    (output_dir / "model_manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result

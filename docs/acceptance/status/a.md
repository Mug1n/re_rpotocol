# A status

- Date: 2026-09-10
- State: `partial` (the deterministic integration and bounded semantic-model path are real; the M01--M11 coverage is incomplete).
- Implemented: `scripts/analyze.py` writes a hash-bound run manifest after validating M01/M09 inputs, the M08 recovered bytes against independent truth, and the C2 classifier model plus a label-free prediction.  It invokes M12 only in its existing deterministic mode.
- Actual run: `data/acceptance/frozen-20260910/integration/run/run_manifest.json` records a complete 101-byte recovery SHA match and an `upload-06` label-free inference result.  The manifest intentionally stays `partial`.
- Model evidence: one authorized DeepSeek `deepseek-v4-flash` call completed using only two compact deterministic observations. `integration/api-run/model/` contains a key-free request record, raw response and hashes. The response has two claims, each constrained to a supplied evidence ID; usage was 337 tokens. The API key was held only in process memory.
- Remaining gate: `integration/api-run/run_manifest.json` remains `partial`, because this demonstration only fed M01/M09 into M12. The verifier correctly returns partial rather than claiming full M01--M11 coverage.

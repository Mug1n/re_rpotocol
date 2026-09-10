# A status

- Date: 2026-09-10
- State: `partial` (the deterministic integration path is real; semantic-model acceptance is blocked).
- Implemented: `scripts/analyze.py` writes a hash-bound run manifest after validating M01/M09 inputs, the M08 recovered bytes against independent truth, and the C2 classifier model plus a label-free prediction.  It invokes M12 only in its existing deterministic mode.
- Actual run: `data/acceptance/frozen-20260910/integration/run/run_manifest.json` records a complete 101-byte recovery SHA match and an `upload-06` label-free inference result.  The manifest intentionally stays `partial`.
- Model gate: this host has no discovered local model executable or endpoint. `experiments/M12/model_adapter.py` reports that state and has no fabricated fallback. M12 also has no bounded semantic-support validator, so no model explanation was invoked.

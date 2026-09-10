# A handoff: integration-run-20260910

- Consumer: C acceptance verifier / final demonstrator.
- Entry point: `python -B scripts/analyze.py --help`; the executed result is `data/acceptance/frozen-20260910/integration/run/run_manifest.json`.
- Recovery evidence: `recovery.status` is `matched`; the recovered output and independent `truth/download-01.json` both bind to SHA-256 `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07`.
- Classification evidence: `upload-06-label-free.json` contains no labels; `upload-06-prediction.json` binds to `model.joblib` SHA-256 `4e7b6dcdeed8310556fdfe163a42dac645e8abf201cfd9aa63390b6c7398dfa5` and predicts `upload` with score `0.95`. This small local HTTP batch is not a generalization claim.
- Blocking condition: no local semantic model is installed/discovered and no bounded semantic validator is implemented. Treat `model.status=blocked` as a required failure gate, not a pass.

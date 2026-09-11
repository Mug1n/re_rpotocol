# 15-minute acceptance demonstration

## 0:00–3:00 — Goal and architecture

Explain that a `.dat` suffix is not a protocol claim. Show the profile-driven graph: M01 content probe and streams; B's protocol/body/structure/recovery path; C's flow, behavior and label-free classification path; A's evidence normalization, bounded model explanation and C's independent gate.

## 3:00–8:00 — Live deterministic run

From a clean checkout run:

```powershell
python -B scripts/analyze.py --input data/acceptance/frozen-20260910/captures/download-01.pcapng --profile profiles/acceptance.json --output-dir tmp/demo-run
```

Open `tmp/demo-run/run_manifest.json`. Verify that M01 and M07 say `reused_verified` on a host without TShark, all other stages completed, M12 has M01–M11 coverage, and the M11 prediction record contains no label input. Show the M08 recovered file and compare its SHA-256 with `data/acceptance/frozen-20260910/truth/download-01.json` without passing truth to the analysis command.

## 8:00–11:00 — Independent acceptance and model evidence

```powershell
python -B scripts/verify_acceptance.py data/acceptance/frozen-20260910/full-chain/acceptance.json
```

Show `acceptance: PASS`, then inspect the saved key-free DeepSeek request, raw response and model manifest. Explain that claims must cite deterministic evidence IDs and that the API key was never persisted. Do not re-call the paid API during the presentation unless the user explicitly authorizes it.

## 11:00–13:00 — Negative cases and limits

Run the A/B/C focused tests or show their saved command results. Demonstrate that missing input, an existing output directory, a tampered parent/hash, truncated HTTP, unsupported Brotli, missing model evidence and incomplete module coverage return non-success. State that no-key TLS/SSH is not decrypted and random/high-entropy bytes are not called encrypted or malicious.

## 13:00–15:00 — Contribution and buffer

Summarize A/B/C ownership and leave member identities as a human-filled item. Keep two minutes for questions or for using the pre-generated frozen outputs if Wireshark or network access is unavailable.

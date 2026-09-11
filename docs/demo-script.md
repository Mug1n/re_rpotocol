# 10 minute acceptance demonstration

## Before the audience arrives

Run from the repository root. Confirm Python and the local Git-ignored TShark/Capinfos 4.6.8 installation. Output directories must be new; change the numeric suffix if a rehearsal already created them.

```powershell
python --version
& ".\third_party\Wireshark\tshark.exe" --version
& ".\third_party\Wireshark\capinfos.exe" --version
```

No network access or model credential is required. Do not add `--invoke-model`. Npcap is not installed on the current host, so demonstrate saved-capture analysis rather than live interface capture.

## 0:00 to 1:00 Goal and architecture

Explain that a `.dat` suffix is not a protocol claim. The graph begins with M01 content detection and byte preservation. B owns protocol/body/structure/recovery evidence, C owns flow/behavior/classification and the independent gate, and A owns orchestration, M12 and bounded model explanation. The trust chain is input hash to scoped module artifacts to recovered/classified/report artifacts to independent acceptance.

## 1:00 to 3:00 Fresh TShark extraction

```powershell
python -B experiments\M01\run.py `
  data\acceptance\frozen-20260910\captures\download-01.pcapng `
  --output-dir tmp\demo-m01-live-01 `
  --tshark ".\third_party\Wireshark\tshark.exe" `
  --capinfos ".\third_party\Wireshark\capinfos.exe"
```

Open `tmp/demo-m01-live-01/result.json`. Show that content evidence identifies PCAPNG and that packet, flow and TCP stream records are produced. State that arbitrary raw DAT input is not promoted to a capture and missing metadata is never fabricated.

## 3:00 to 6:00 ABC integration run

```powershell
python -B scripts\analyze.py `
  --input data\acceptance\frozen-20260910\captures\download-01.pcapng `
  --profile profiles\acceptance.json `
  --output-dir tmp\demo-abc-run-01 `
  --tshark ".\third_party\Wireshark\tshark.exe"
```

Inspect `tmp/demo-abc-run-01/run_manifest.json`. Its status should be `complete`. M01, M07 and M11 are `reused_verified` because the acceptance profile deliberately preserves hash-locked offline evidence; the preceding fresh M01 command separately demonstrates current-host TShark execution. Other selected stages complete locally, M12 covers M01–M11, and the analysis command receives neither truth nor labels.

## 6:00 to 8:00 Recovery classification and report

```powershell
Get-ChildItem tmp\demo-abc-run-01\m08\0000\recovered\*.bin | Get-FileHash -Algorithm SHA256
Get-Content -Raw tmp\demo-abc-run-01\m11\prediction.json
Get-Content -Raw tmp\demo-abc-run-01\m12\report_manifest.json
```

The recovered 101 bytes should have SHA-256 `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07`. The same `download-01` flow receives the label-free prediction `download` with score 0.985. Describe that score as this controlled model's class probability for this flow, not a universal accuracy claim. M12 is a deterministic evidence report; the saved DeepSeek record is key-free and does not decide acceptance.

## 8:00 to 9:00 Independent acceptance

```powershell
python -B scripts\assemble_acceptance.py `
  --run-manifest tmp\demo-abc-run-01\run_manifest.json `
  --truth data\acceptance\frozen-20260910\truth\download-01.json `
  --classifier-evaluation data\acceptance\frozen-20260910\classification\model-run\evaluation.json `
  --model-manifest data\acceptance\frozen-20260910\integration\api-run\model\model_manifest.json `
  --output tmp\demo-abc-acceptance-01.json
python -B scripts\verify_acceptance.py tmp\demo-abc-acceptance-01.json
```

Show the final line `acceptance: PASS`. Truth enters only after analysis, in the assembler. C's verifier independently checks hashes, source binding, recovery truth, label-free prediction, M12 coverage and model evidence.

If a live command fails, use the committed formal record without hiding the failure:

```powershell
python -B scripts\verify_acceptance.py reports\acceptance\2026-09-11-abc\acceptance.json
```

## 9:00 to 10:00 Limits and questions

State the boundaries directly: the 18 loopback HTTP captures are controlled acceptance evidence rather than broad classifier validation; no-key TLS/SSH is not decrypted; Brotli remains unsupported; high entropy is not called malicious or encrypted; and the main M03 boundary is protocol-declared from the HTTP body rather than automatic unknown-protocol discovery. The current host can analyze saved captures but needs a system Npcap driver for live interface capture.

Close with: the project's main result is a reproducible evidence chain. Every supported conclusion is scoped and hash-bound, unsupported conclusions degrade explicitly, and an independent gate rather than the analysis program decides PASS.

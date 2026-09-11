# Role A handoffs

## A-G3-ABC-20260911

- producer：A integration；consumers：C 独立验收、B 证据语义复核、最终演示者
- tasks：A1～A3 / G0～G4 code path
- code_ref：`91e52dcf3e213b1a0f1fd8c6296de50383a7b40e`
- branch：`codex/acceptance-integration`
- status：`ready_for_human_signoff`；独立代码 gate 已 PASS，当前主机的 TShark 真实提取测试也已通过，但不代替真实成员签字、实时网卡采集或课程指定 DAT。

### Interfaces

- G0 contract：`docs/interfaces/acceptance-pipeline-contract.md`
- profile Schema：`research/analysis-profile.schema.json`，版本 0.1
- run Schema：`research/run-manifest.schema.json`，版本 0.1
- final acceptance Schema：`research/acceptance.schema.json`，版本 0.1（C owner）

### Artifacts

| artifact | SHA-256 | result |
|---|---|---|
| `reports/acceptance/2026-09-11-abc/run/run_manifest.json` | `5a60bb80e68af384c0ee79a02a12b3a468adb83b1b2579fdcf0e395f72daa267` | 14 stages complete/reused; M01–M11 delivered to M12 |
| `reports/acceptance/2026-09-11-abc/run/m08/0000/recovered/m08-215ff970eee6-0000.bin` | `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07` | 101-byte truth match |
| `reports/acceptance/2026-09-11-abc/run/m11/prediction.json` | `db973239e25e231661888f7bcc960d4c5a08ddfb9502902e35d50150bb0272fe` | same-input label-free `download`, score 0.985 |
| `reports/acceptance/2026-09-11-abc/run/m12/report_manifest.json` | `9b8e1def93c81e00786498a5ddd26dedc6251b8b5b03f512e7217f52d80ceada` | complete M01–M11 coverage |
| `reports/acceptance/2026-09-11-abc/acceptance.json` | `3058003e4264783e9721e1148aa898d487ee655dd57b50ec12d393be097ed8ef` | C verifier PASS |

Source capture is C's frozen `download-01.pcapng`; truth is supplied only to `assemble_acceptance.py`, never to `analyze.py`. The persisted real DeepSeek records remain under `data/acceptance/frozen-20260910/integration/api-run/model/` and contain no API key.

### Re-run

```powershell
python -B scripts/analyze.py --input data/acceptance/frozen-20260910/captures/download-01.pcapng --profile profiles/acceptance.json --output-dir tmp/abc-run
python -B scripts/assemble_acceptance.py --run-manifest tmp/abc-run/run_manifest.json --truth data/acceptance/frozen-20260910/truth/download-01.json --classifier-evaluation data/acceptance/frozen-20260910/classification/model-run/evaluation.json --model-manifest data/acceptance/frozen-20260910/integration/api-run/model/model_manifest.json --output tmp/abc-acceptance.json
python -B scripts/verify_acceptance.py tmp/abc-acceptance.json
```

Expected final line is `acceptance: PASS`. The output paths must not already exist. Do not add `--invoke-model` unless a new external call is explicitly authorized.

### Consumer checks

- B：review that model claims do not exceed their cited deterministic observations and that protocol-declared framing is not called automatic discovery.
- C：rerun the verifier, compare recovered bytes to frozen truth, and confirm prediction/model/source binding. This document does not claim that a human C member has signed.
- Demonstrator：run the package in a new directory, install TShark separately if fresh capture extraction is required, and fill only verified member identities/contributions. The local ignored path is `third_party/Wireshark/tshark.exe`.

### Known limits

- Current host has TShark/Capinfos 4.6.8 in ignored `third_party/Wireshark/`; all 168 tests pass with `WIRESHARK_HOME` set. M01/M07 remain verified frozen reuse in `profiles/acceptance.json` for offline reproducibility.
- Npcap is not installed, so existing captures can be analyzed but live interface capture is not part of this host verification.
- The 18 loopback captures are small controlled evidence, not broad classifier validation.
- Brotli and no-key TLS/SSH remain explicit unsupported/skipped cases.
- Human PPT finalization, screenshots/video and course-specific input are outside automated evidence.

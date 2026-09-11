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
| `reports/acceptance/2026-09-11-abc/run/run_manifest.json` | `715d5b7e9e7d5d8ef379f2ba1306b317bb7795ef1c285d3ced583918559ef833` | 14 stages complete/reused; M01–M11 delivered to M12 |
| `reports/acceptance/2026-09-11-abc/run/m08/0000/recovered/m08-215ff970eee6-0000.bin` | `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07` | 101-byte truth match |
| `reports/acceptance/2026-09-11-abc/run/m11/prediction.json` | `64811820e53776def7d6e1ad36a75ba14935350ec21fecf1685277b7629f4086` | same-input label-free `download`, score 0.99 |
| `reports/acceptance/2026-09-11-abc/run/m12/report_manifest.json` | `e40e30753a7005eb34054e8c7cb95be84774e6c602673e6211011d9276b8bb42` | complete M01–M11 coverage |
| `reports/acceptance/2026-09-11-abc/acceptance.json` | `95bf5b6c0ff7d8f418079ca75a56905f5453d2d5b62a64ef064e2c56f0fd9946` | C verifier PASS |

2026-09-11 复现修订：该记录在本主机原样重跑生成，M11 阶段由临时 C2 分类器改为 M11 原生 v0.2 分类器（`classification/m11-v0.2/`），并修掉 `analysis-profile` 复用路径的绝对路径记录（现全部为仓库相对路径）。因此上表 run/预测/M12/acceptance 四个哈希相对本节首次签署时已变，`m08` 恢复字节哈希不变。

Source capture is C's frozen `download-01.pcapng`; truth is supplied only to `assemble_acceptance.py`, never to `analyze.py`. The persisted real DeepSeek records remain under `data/acceptance/frozen-20260910/integration/api-run/model/` and contain no API key.

### Re-run

```powershell
python -B scripts/analyze.py --input data/acceptance/frozen-20260910/captures/download-01.pcapng --profile profiles/acceptance.json --output-dir tmp/abc-run
python -B scripts/assemble_acceptance.py --run-manifest tmp/abc-run/run_manifest.json --truth data/acceptance/frozen-20260910/truth/download-01.json --classifier-evaluation data/acceptance/frozen-20260910/classification/m11-v0.2/run/classification.json --model-manifest data/acceptance/frozen-20260910/integration/api-run/model/model_manifest.json --output tmp/abc-acceptance.json
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

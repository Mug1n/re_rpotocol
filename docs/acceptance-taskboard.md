# ABC acceptance taskboard

Updated: 2026-09-11. Integration branch: `codex/acceptance-integration`.

| Gate/work package | State | Evidence |
|---|---|---|
| G0 interface contract | ready_for_consumer | `docs/interfaces/acceptance-pipeline-contract.md`, profile/run schemas |
| A1 single-input pipeline | verified_local | 5 A pipeline tests; formal run manifest |
| A2 actual model and report | verified_by_gate | persisted key-free DeepSeek call; 5 model-adapter negative/positive tests; C verifier checks raw response |
| A3 integration/release code | ready_for_human_signoff | formal ABC acceptance PASS; clean-package new-directory replay PASS |
| B1–B3 protocol/recovery | merged / producer-ready | B commits `7625ca0`, `b7a1412`; payload tests 16/16 |
| C1 data/truth | merged / gate-consumed | 18 frozen captures and separated truth; manifest tests pass |
| C2 classification | merged / gate-consumed | grouped controlled evaluation, hash-bound model and same-input label-free prediction |
| C3 independent gate | verified_code | `scripts/verify_acceptance.py` returns PASS on formal ABC artifact |

## Acceptance cases

| Case | Current result | Boundary |
|---|---|---|
| AC01 self-captured HTTP DAT | PASS on frozen main artifact | current host reuses hash-verified TShark 4.6.8 M01/M07 |
| AC02 native length raw DAT | PASS in real-DAT tests | WatchPAT structure evidence; no network metadata claim |
| AC03 independent classification | PASS for controlled split/new-input path | tiny loopback dataset, no generalization claim |
| AC04 random/damaged/encrypted | PASS in negative tests | Brotli/no-key encryption explicitly unsupported |
| AC05 missing prerequisites | PASS in failure/degradation tests | missing model/tool never becomes acceptance success |
| AC06 tampering/multi-source | PASS in hash and M12 multi-artifact tests | final acceptance currently selects one artifact per module |
| AC07 clean-directory replay | PASS for saved captures | offline package replay PASS; current host fresh M01/TShark extraction and all 168 tests PASS; live capture still needs Npcap |

## Remaining non-code signoff

- Three real members must fill names and confirm contribution percentages totaling 100%.
- C must assemble final PPT/screenshots/video; A/B content is under `docs/delivery/` and `docs/demo-script.md`.
- If a course-designated DAT exists, run and report it separately before submission.

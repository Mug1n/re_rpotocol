# C handoffs

## C3-independent-model-verifier-001

- Consumer: final acceptance. Input: `data/acceptance/frozen-20260910/integration/api-run/run_manifest.json`.
- C verifies model-manifest, request and response hashes; requires `key_persisted=false`, parses raw response claims, and permits only evidence IDs in the deterministic M12 evidence file.
- Current outcome is non-pass: `PARTIAL` because M02--M08 and M10--M11 are not included in the same M12 input coverage.

## C3-full-chain-001

- Consumer: final acceptance. Artifact: `data/acceptance/frozen-20260910/full-chain/acceptance.json`.
- The acceptance schema requires a hash-bound input record, deterministic report, recovery, classification and model record. The verifier cross-checks that all M01--M11 entries equal M12's own input records.
- Re-run: `python -B scripts/verify_acceptance.py data/acceptance/frozen-20260910/full-chain/acceptance.json` returns `acceptance: PASS` (exit 0).
- Scope note: full coverage is proven; M03 remains partial and M06 empty for this one response flow, and those are preserved as module limitations.

## C-public-replay-001

- Artifact: `reports/public-samples/2026-09-10-c-public-evaluation-final/README.md` and `summary.json`, with 21 linked per-sample reports.
- Re-run used the frozen local corpus and TShark for capture inputs; no replay or external network traffic occurred.
- Result: 21 `completed_with_limits`, 0 module failures. The merger independently rejects any missing/duplicate artifact or mismatch against the frozen public-manifest SHA-256 and byte size.

## C2-feature-adapter-001

- producer：C；consumer：A；任务：C2；code_ref：`c7f7fc099be97d5358350430f441450b9db57d22`（`codex/acceptance-c-behavior`）。
- 代码：`experiments/M11/build_rows.py` 将 M09 流记录转为固定版本、无标签特征行；`experiments/M11/predict.py` 只接受模型 artifact 哈希与特征版本均一致的无标签输入。
- 重跑：`python -B -m unittest discover -s experiments/M11/tests -v`；2026-09-10 退出码 0，11 项通过。
- 消费检查：A 应使用已保存的 `classification.json`/`model.joblib` 和未含标签的 M09 特征行运行 `predict.py`，并将 prediction artifact 加入运行清单；尚不可将此测试用模型当作真实采集分类结论。
- 未完成：没有来自 B 的可采集服务、冻结的主 DAT/正文与独立 truth，也没有 A 的运行清单契约。因此 C1 的真实采集和 C3 的独立全链验收均未开始，不存在可交付的验收批次。

尚无可供 A/B 消费的冻结采集批次。待 B 交付服务后，首批记录将包含相对路径、SHA-256、任务/分组、独立 truth 及重跑命令；标签不会写入分析输入。

## C1-capture-001

- producer：C；consumers：A、B；任务：C1；code_ref：待本批提交。
- artifact：`data/acceptance/frozen-20260910/manifest.json`，含 18 个独立 loopback HTTP PCAPNG；`truth/` 中每个任务独立记录响应哈希和操作。分析模块不得读取 truth。
- 分区：download/upload/periodic 各 4 train、1 validation、1 test；每项任务独立 group_id。
- 重跑：先按 B-G1-local-001 启动服务，再运行 `python -B scripts/capture_acceptance_samples.py --tshark <path> --output-root data/acceptance/frozen-<date>`；输出目录必须为新目录。
- 已验证：所有 capture SHA-256 与 manifest 一致、文件非空；`upload-01.pcapng` 的 TShark TCP conversation 显示 15 个帧、1231 bytes。周期任务使用同一 keep-alive HTTP 连接连续发出四次请求。

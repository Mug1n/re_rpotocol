# C status

## 2026-09-10 actual C1/C2/C3 evidence update

- C1: 18 frozen local loopback HTTP PCAPNG samples exist under `data/acceptance/frozen-20260910/`, with six each for download/upload/periodic and fixed 4/1/1 train/validation/test groups. Capture hashes and non-empty files were checked.
- C2: `classification/model-run/evaluation.json` records a hash-bound RandomForest model and tiny controlled validation/test macro-F1 values of 1.0. `integration/upload-06-label-free.json` contains no labels; its hash-validated model prediction is in `integration/upload-06-prediction.json`.
- C3: `integration/recovery/recovery.json` recovered 101 bytes for download-01; `integration/run/run_manifest.json` confirms the recovered SHA-256 equals independent truth. It remains `partial` because the real semantic-model gate is blocked, not because recovery or classifier inference was skipped.

## 2026-09-10 C3 model-evidence integration

- C's verifier now independently checks A's persisted DeepSeek request/response and model-manifest SHA-256 values, confirms that raw response JSON equals the recorded claims, and rejects citations outside M12's deterministic evidence set.
- Positive run returned the required `PARTIAL` status (exit 3): model invocation, recovery and label-free classification verify, but M01--M11 coverage is incomplete.
- Negative run changed only the recorded model-manifest SHA-256 and returned `acceptance: FAIL: model manifest hash mismatch` (exit 2).

- role：C；更新时间：2026-09-10；分支：`codex/acceptance-c-behavior`；基线：`a935fbdba601ce163f7c4d44c806c09efdc71246`。
- C2：`ready_for_consumer`（代码层）。新增 M09→固定特征行适配及模型哈希校验的新输入推理入口；`python -B -m unittest discover -s experiments/M11/tests -v` 于 2026-09-10 退出码 0，11 项通过。尚待冻结的训练/验证/测试分区与真实采集数据后才能形成真实分类指标。
- C1：`ready_for_consumer`。基于 B 的本地回环服务实际采集 18 个 HTTP PCAPNG（下载/上传/周期各 6），冻结于 `data/acceptance/frozen-20260910/`。每类按 4/1/1 固定 train/validation/test，输入哈希与非空长度均已复核；truth 与分析输入分文件保存。TShark 4.6.8、Npcap loopback 接口 10。尚待 B 对正文恢复做独立语义核对，以及 A 消费主例。
- C3：`blocked`。A 的 `scripts/analyze.py`、运行清单 Schema 和真实模型调用记录尚未交付；独立验收脚本无法对不存在的入口假称通过。
- 本批修改：`experiments/M11/build_rows.py`、`experiments/M11/predict.py`、`experiments/M11/tests/test_predict.py`、`experiments/M11/README.md`、本状态和交接文件。未生成或提交任何伪造数据、模型、预测或验收报告。

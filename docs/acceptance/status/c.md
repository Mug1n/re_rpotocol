# C status

更新时间：2026-09-11。下列状态取代本文件此前的阶段性 `blocked` 记录；历史过程保留在 Git 提交中。

## 当前结论

- C1 `complete`：`data/acceptance/frozen-20260910/` 保存 18 个本地回环 HTTP PCAPNG，download/upload/periodic 各 6 个，按任务固定为 4/1/1 train/validation/test。抓包、独立 truth、非空长度与 SHA-256 均已冻结。
- C2 `complete`：M11 已具备固定 17 维特征、隔离标签准备、分组不泄漏训练、冻结模型推理及留出集评估。`classification/model-run/evaluation.json` 保存受控闭环指标；`integration/upload-06-label-free.json` 不含标签，预测结果单独保存。
- C3 `complete`：正式 ABC 产物为 `reports/acceptance/2026-09-11-abc/acceptance.json`，`scripts/verify_acceptance.py` 返回 `acceptance: PASS`。恢复结果为 101 字节，SHA-256 `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07`，并与独立 truth 一致。
- 外部评测 `complete_with_limits`：ISCX VPN-nonVPN 2016 的 28 个 VPN 会话、1028 条 flow 完成 2 折会话不交叠业务分类评测，macro-F1 均值 0.4995，多数类基线 0.3040。它不覆盖 VPN 状态分类，也不替代正式 ABC 验收。

## 当前复核

- Python 3.13.9；TShark/Capinfos 4.6.8 位于 Git 忽略的 `third_party/Wireshark/`。
- M01～M12 与共享回归共 183 项：183 通过、0 跳过。
- `python -B scripts/reproduce_iscx_evaluation.py verify` 可在没有 2.3 GB 原始包时核验 ISCX manifest、折分、行数、混淆矩阵和派生指标；提供原始抓包后用 `prepare`、`train` 完整复跑。

## 保留限制

- 当前主机没有 Npcap，因此可复跑保存抓包，但不能现场重新采集接口流量。
- ISCX 原始抓包不进入 Git；实际归档来自记录的 Kaggle 镜像，与失效的 UNB 官方归档未作独立字节等价证明。
- 三位成员实名贡献、最终 PPT 截图与演示录像仍需人工确认。

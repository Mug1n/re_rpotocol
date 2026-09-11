# C handoffs

本页只保留当前可消费交付；早期 `blocked` / `partial` 交接可从 Git 历史追溯。

## C3-abc-acceptance-final

- Consumer：最终验收与演示。
- Artifact：`reports/acceptance/2026-09-11-abc/acceptance.json`。
- Re-run：`python -B scripts/verify_acceptance.py reports/acceptance/2026-09-11-abc/acceptance.json`，预期 `acceptance: PASS`（退出码 0）。
- Boundary：PASS 证明输入、M01～M12、恢复、分类和模型记录的哈希绑定与规则一致；不把 M03 的 partial 或 M06 的 empty 伪装成语义成功。

## C1-frozen-captures-final

- Consumers：A、B 与最终验收。
- Artifact：`data/acceptance/frozen-20260910/manifest.json`，含 18 个独立 loopback HTTP PCAPNG；`truth/` 独立保存响应哈希和操作，分析模块不得读取 truth。
- Partition：download/upload/periodic 各 4 train、1 validation、1 test；每项任务使用独立 `group_id`。
- Re-capture：先启动 `scripts/acceptance_http_server.py`，再运行 `python -B scripts/capture_acceptance_samples.py --tshark <path> --output-root data/acceptance/frozen-<date>`；输出目录必须不存在，现场重采需要 Npcap。

## C2-m11-final

- Consumers：A 与最终验收。
- Code：`experiments/M11/` 提供 build/prepare/train/evaluate/predict 闭环；模型、特征版本和输入均由哈希绑定。
- Controlled artifacts：`data/acceptance/frozen-20260910/classification/` 与 `integration/upload-06-prediction.json`。
- External evidence：`data/external/iscx-vpn-2016/manifest.json`、`evaluation.json`；`python -B scripts/reproduce_iscx_evaluation.py verify` 可离线复核，`prepare` / `train` 在提供哈希匹配的原始抓包后完整复跑。
- Boundary：ISCX 数字仅表示真实 VPN 抓包上的 application 分类基线，不表示 VPN/non-VPN 分类能力。

## C-public-replay-final

- Artifact：`reports/public-samples/2026-09-10-c-public-evaluation-final/README.md` 与 `summary.json`，关联 21 个样例报告。
- Result：21 个 `completed_with_limits`、0 个模块失败；合并器拒绝缺失、重复或与冻结 manifest 大小/SHA-256 不符的输入。

# C handoffs

## C2-feature-adapter-001

- producer：C；consumer：A；任务：C2；code_ref：`c7f7fc099be97d5358350430f441450b9db57d22`（`codex/acceptance-c-behavior`）。
- 代码：`experiments/M11/build_rows.py` 将 M09 流记录转为固定版本、无标签特征行；`experiments/M11/predict.py` 只接受模型 artifact 哈希与特征版本均一致的无标签输入。
- 重跑：`python -B -m unittest discover -s experiments/M11/tests -v`；2026-09-10 退出码 0，11 项通过。
- 消费检查：A 应使用已保存的 `classification.json`/`model.joblib` 和未含标签的 M09 特征行运行 `predict.py`，并将 prediction artifact 加入运行清单；尚不可将此测试用模型当作真实采集分类结论。
- 未完成：没有来自 B 的可采集服务、冻结的主 DAT/正文与独立 truth，也没有 A 的运行清单契约。因此 C1 的真实采集和 C3 的独立全链验收均未开始，不存在可交付的验收批次。

尚无可供 A/B 消费的冻结采集批次。待 B 交付服务后，首批记录将包含相对路径、SHA-256、任务/分组、独立 truth 及重跑命令；标签不会写入分析输入。

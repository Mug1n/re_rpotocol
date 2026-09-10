# C status

- role：C；更新时间：2026-09-10；分支：`codex/acceptance-c-behavior`；基线：`a935fbdba601ce163f7c4d44c806c09efdc71246`。
- C2：`ready_for_consumer`（代码层）。新增 M09→固定特征行适配及模型哈希校验的新输入推理入口；`python -B -m unittest discover -s experiments/M11/tests -v` 于 2026-09-10 退出码 0，11 项通过。尚待冻结的训练/验证/测试分区与真实采集数据后才能形成真实分类指标。
- C1：`blocked`。B 的 `scripts/acceptance_http_server.py`、可采集服务命令和主正文尚未交付，仓库没有 `data/acceptance/`；不能伪造 HTTP 采集、真值或标签。
- C3：`blocked`。A 的 `scripts/analyze.py`、运行清单 Schema 和真实模型调用记录尚未交付；独立验收脚本无法对不存在的入口假称通过。
- 本批修改：`experiments/M11/build_rows.py`、`experiments/M11/predict.py`、`experiments/M11/tests/test_predict.py`、`experiments/M11/README.md`、本状态和交接文件。未生成或提交任何伪造数据、模型、预测或验收报告。

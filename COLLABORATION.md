# pc1 分支协作说明

更新日期：2026-09-08。本分支从 `origin/main` 的 `4d1f23e` 创建，集中交付 M01～M06 的可运行基线、测试、JSON Schema、两个真实外部 DAT 及验证记录。课程尚未提供最终 DAT，因此当前结果用于开发与接口验证，不代表对隐藏数据的最终适配。

## 当前链路

```text
M01 输入识别与预处理
  → M02 基础字节特征
  → M03 显式消息分帧
  → M04 DBSCAN 消息聚类
  → M05 代表消息参考对齐
  → M06 字段/边界及长度关系假设
```

各模块都提供 `experiments/Mxx/run.py`、模块 README 和测试；结构化输出 Schema 位于对应的 `research/Mxx-*` 目录。权威工程状态见 `research/progress.md`，总体入口和命令见根目录 `README.md`。

## 真实数据与已验证结论

- `data/external/raw/audiobeat-octapro/dsp_m2.dat`：2387 字节设备预设。M03 从偏移 5 起切出 10 个 238 字节块，源字节覆盖完整；M04 探索参数 `eps=0.11` 得到 4 簇；M05 对齐 10/10 条，平均配对字节一致率约 0.9684；M06 不报告长度字段。
- `data/external/raw/watchpat/testdata.dat`：8469 字节、15 条长度前缀 BLE 记录。M03 使用 `[u32le payload_length][payload]` 完整切分；M06 在 15 条记录中复现偏移 0 的 4 字节小端 payload-length 关系，并观察到偏移 20 的重复长度候选。
- 数据来源提交、SHA-256、许可和使用限制记录在 `data/external/manifest.json`；许可副本随仓库保存。WatchPAT 样本涉及生理数据研究场景，不应尝试识别或传播个人身份信息。
- 完整参数、指标和限制见 `data/external/validation.md`。聚类编号、对齐一致率和统计字段候选都不是协议语义真值。

## 复测

在仓库根目录运行：

```powershell
python -B -m unittest discover -s experiments\M01\tests -v
python -B -m unittest discover -s experiments\M02\tests -v
python -B -m unittest discover -s experiments\M03\tests -v
python -B -m unittest discover -s experiments\M04\tests -v
python -B -m unittest discover -s experiments\M05\tests -v
python -B -m unittest discover -s experiments\M06\tests -v
python -B -m unittest discover -s experiments\tests -v
```

当前环境共运行 58 项：54 项通过，M01 的 4 项抓包测试因未安装 Wireshark CLI 而明确跳过。M02～M06 的运行代码只依赖 Python 标准库；Schema 测试需要当前开发环境已有的 `jsonschema`。

## 协作约定与已知限制

- 不要提交 `tmp/`、`__pycache__/` 或本地虚拟环境；它们已被 `.gitignore` 排除。
- 各 CLI 默认拒绝覆盖既有输出目录。复跑时使用新目录，以保留参数和来源证据。
- `.dat` 只是扩展名；不要在未检查内容时假定它是抓包、加密流量或某种固定协议。
- M03 当前是显式规则分帧，不声称从任意未知流自动发现边界。
- M04 使用 O(n²) 距离矩阵；M05 是以代表消息为锚的确定性对齐，不是全局最优多序列对齐。
- M06 的连续统计区间是候选而非真实字段。WatchPAT 默认单簇对齐较碎，说明应同时检查 M04/M05 质量。
- 当前机器缺少 Wireshark/TShark，因此 M01 抓包路径尚未在本轮环境复测；不要把历史运行记录表述为当前复测结果。
- 开始新模块前先读 `agent.md` 和 `research/progress.md`；修改模块接口时同步更新下游测试、Schema、根 README 和真实验证记录。

## 建议分工入口

- M07：标准协议识别；需要恢复 Wireshark/TShark 后验证抓包路径。
- M08：可见文本、编码与压缩恢复；必须区分编码、压缩和加密。
- M09～M11：只有输入保留包边界、时间戳、方向和标签时才能进行相应流量与分类分析。
- M12：只解释结构化证据，不替代解析器或捏造协议语义。

合并本分支前，建议先运行上述全套测试，并重点审阅 `data/external/validation.md` 中公开样本与课程最终 DAT 的边界说明。

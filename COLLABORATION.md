# pc1 分支协作说明

> **Codex执行入口：** 先读 [执行契约](docs/acceptance/codex-execution-contract.md)，再按分配角色读 [A](docs/acceptance/role-a.md)、[B](docs/acceptance/role-b.md) 或 [C](docs/acceptance/role-c.md)。每个入口包含读取顺序、写入范围、依赖、交接和启动提示词。以门禁和实际证据推进，不按下文历史状态或人类会议时间等待。

> 三人团队的后续验收冲刺以 [三人团队验收协作计划](docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md) 为分工与交接依据，以 [PDF验收闭环方案](docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md) 为验收标准。新计划明确 A（集成/报告/大模型）、B（协议/结构/还原）、C（数据/分类/独立验收）的文件所有权；下文既有记录保留作历史背景。

更新日期：2026-09-10。本分支从 `origin/main` 的 `4d1f23e` 创建，现已汇合 M01～M12 的可运行基线、测试、JSON Schema、两个真实外部 DAT 及验证记录。课程尚未提供最终 DAT，因此当前结果用于开发与接口验证，不代表对隐藏数据的最终适配。

## 当前链路

```text
M01 输入识别与预处理
  → M02 基础字节特征
  → M03 显式消息分帧
  → M04 DBSCAN 消息聚类
  → M05 代表消息参考对齐
  → M06 字段/边界及长度关系假设
  → M07 标准协议证据 / M08 受限内容恢复
  → M09 流量特征 → M10 非语义行为规则 → M11 条件式分类评估
  → M12 可追溯证据报告
```

各模块都提供 `experiments/Mxx/run.py`、模块 README 和测试；结构化输出 Schema 位于对应的 `research/Mxx-*` 目录。权威工程状态见 `research/progress.md`，总体入口和命令见根目录 `README.md`。

## 真实数据与已验证结论

- `data/external/raw/audiobeat-octapro/dsp_m2.dat`：2387 字节设备预设。M03 从偏移 5 起切出 10 个 238 字节块，源字节覆盖完整；M04 探索参数 `eps=0.11` 得到 4 簇；M05 对齐 10/10 条，平均配对字节一致率约 0.9684；M06 不报告长度字段。
- `data/external/raw/watchpat/testdata.dat`：8469 字节、15 条长度前缀 BLE 记录。M03 使用 `[u32le payload_length][payload]` 完整切分；M06 在 15 条记录中复现偏移 0 的 4 字节小端 payload-length 关系，并观察到偏移 20 的重复长度候选。
- 数据来源提交、SHA-256、许可和使用限制记录在 `data/external/manifest.json`；许可副本随仓库保存。WatchPAT 样本涉及生理数据研究场景，不应尝试识别或传播个人身份信息。
- 完整参数、指标和限制见 `data/external/validation.md`。聚类编号、对齐一致率和统计字段候选都不是协议语义真值。
- 新增 21 个小型公共协议样例，来源于固定提交的 NetPlier、BinaryInferno 和 Wireshark；清单见 `data/external/test-samples-manifest.json`，本机验证见 `data/external/test-samples-validation.md`。ZeroAccess/Mirai 只允许离线解析，禁止回放。

## 复测

在仓库根目录运行：

```powershell
python -B -m unittest discover -s experiments\M01\tests -v
python -B -m unittest discover -s experiments\M02\tests -v
python -B -m unittest discover -s experiments\M03\tests -v
python -B -m unittest discover -s experiments\M04\tests -v
python -B -m unittest discover -s experiments\M05\tests -v
python -B -m unittest discover -s experiments\M06\tests -v
python -B -m unittest discover -s experiments\M07\tests -v
python -B -m unittest discover -s experiments\M08\tests -v
python -B -m unittest discover -s experiments\M09\tests -v
python -B -m unittest discover -s experiments\M10\tests -v
python -B -m unittest discover -s experiments\M11\tests -v
python -B -m unittest discover -s experiments\M12\tests -v
python -B -m unittest discover -s experiments\tests -v
```

当前环境共发现 136 项：130 项通过，6 项因未检测到 TShark 而跳过。覆盖公共样例完整性、M09～M11 严格契约、模型文件校验、M01～M11 到 M12 的记录级适配及双线跨模块集成。M02～M06 的运行代码只依赖 Python 标准库；抓包路径依赖 TShark，M11 成功训练路径依赖 scikit-learn/joblib，Schema 测试依赖 `jsonschema`。

## 协作约定与已知限制

- 不要提交 `tmp/`、`__pycache__/` 或本地虚拟环境；它们已被 `.gitignore` 排除。
- 各 CLI 默认拒绝覆盖既有输出目录。复跑时使用新目录，以保留参数和来源证据。
- `.dat` 只是扩展名；不要在未检查内容时假定它是抓包、加密流量或某种固定协议。
- M03 当前是显式规则分帧，不声称从任意未知流自动发现边界。
- M04 使用 O(n²) 距离矩阵；M05 是以代表消息为锚的确定性对齐，不是全局最优多序列对齐。
- M06 的连续统计区间是候选而非真实字段。WatchPAT 默认单簇对齐较碎，说明应同时检查 M04/M05 质量。
- 仓库已有环境曾记录 TShark 4.6.6 的 M01→M07 冒烟；当前复测环境未安装 TShark。公共评估器可用 `--tshark <path>` 同时传给 M01 与 M07，复跑结果必须注明实际工具版本。
- 开始新模块前先读 `agent.md` 和 `research/progress.md`；修改模块接口时同步更新下游测试、Schema、根 README 和真实验证记录。

## 当前开发分工与交接

- M09～M11 已完成第二轮契约强化：严格 Schema、直接来源哈希、有限数值、原子发布和错误路径测试均已覆盖。
- M01→M09→M10→M12 的来源哈希链和 M11→M12 的分组评估证据均有端到端测试；M03～M06 也已使用记录级证据适配，缺失模块仍会在报告中明确列入“无法判断”。
- M11 只在显式标签、固定数值特征和类别完整的分组拆分满足时训练；无标签、单类别、无法保持各类的分组拆分或依赖缺失时不生成伪指标。成功训练会发布并哈希 `model.joblib`。
- 当前 U8 的代码与合成/契约验收已完成；课程真实 DAT 的协议可见性、标签可用性和最终效果仍是外部验收条件。

合并本分支前，建议先运行上述全套测试，并重点审阅 `data/external/validation.md` 中公开样本与课程最终 DAT 的边界说明。

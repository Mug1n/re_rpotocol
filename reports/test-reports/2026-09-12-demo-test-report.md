# 私有协议分析器演示测试报告

## 1. 基本信息

| 项目 | 内容 |
| --- | --- |
| 测试日期 | 2026-09-12 |
| 被测版本 | `li3` 分支，提交 `9cd0228`（`feat: rank high-confidence field boundaries`） |
| 测试目标 | 验证 M01--M12 证据链、自动化回归测试，以及对未见消息的未知协议推断演示。 |
| 运行环境 | Windows；`C:\\Users\\33395\\anaconda4\\python.exe`；测试进程未自动发现 TShark/capinfos。 |

本报告中的“字段”均严格称为**字段候选**：系统只依据字节稳定性、长度关系和跨消息一致性提出边界候选，不把候选自动解释为字段语义。

## 2. 测试范围与方法

### 2.1 冻结验收链路

执行命令：

```powershell
C:\Users\33395\anaconda4\python.exe -B scripts\verify_acceptance.py `
  data\acceptance\frozen-20260910\full-chain\acceptance.json
```

验收器独立核对输入工件、SHA-256、恢复结果、分类模型工件、模型调用证据和 M12 报告清单。

### 2.2 自动化回归测试

对 `experiments\M01` 至 `experiments\M12` 的 `tests` 目录，以及 `experiments\tests` 集成测试目录，逐一执行：

```powershell
C:\Users\33395\anaconda4\python.exe -B -m unittest discover -s <测试目录> -v
```

### 2.3 未知协议留出集演示

使用固定的 Wireshark UBX 公开抓包衍生的留出消息集。分析阶段不读取该集的真值；流水线完成后才加载独立真值并评分。评估产物：

`reports\unknown-private\wireshark-ubx-heldout-v1-ranked-v2\held_out_evaluation.json`

## 3. 测试结果

### 3.1 冻结验收

结果：**PASS**，命令退出码为 0。

- M01--M11 的工件契约均被提供并通过哈希核验；M12 生成确定性证据报告。
- M08 恢复结果与独立真值匹配：恢复文件为 101 字节，SHA-256 为 `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07`。
- M11 在该小型、受控冻结批次上的验证集和测试集 Macro-F1 均为 1.0。该数值只说明此冻结批次通过，不代表对所有真实流量都达到 1.0。
- 该验收中 M03 的状态为 `partial`、M06 的状态为 `empty`；`PASS` 表示全部模块工件契约和可追溯证据齐全，**不表示每个模块在这份流量上都产生完整业务结果**。

### 3.2 自动化回归

| 指标 | 结果 |
| --- | ---: |
| 总测试数 | 147 |
| 通过 | 141 |
| 失败 | 0 |
| 跳过 | 6 |
| 总结 | **通过（含环境相关跳过）** |

6 项跳过项均属于 M01 对真实抓包工具的测试，原因是本次测试进程没有自动找到 `tshark` 或 `capinfos`，并非断言失败。跳过范围包括：真实 DAT/PCAP 解析、工具失败的原子输出、重传去重、截断抓包标记以及基于内容识别 PCAP/PCAPNG。其余 M01--M12 单元测试与跨模块测试均通过。

### 3.3 未知协议留出集评估

| 指标 | 结果 |
| --- | ---: |
| 留出集消息数 | 639 |
| 完整消息边界匹配率 | 1.000 |
| 内部边界 Precision / Recall / F1 | 1.000 / 1.000 / 1.000 |
| 消息类型 ARI / NMI | 1.000 / 1.000 |
| 高置信字段候选数 | 1,917 |
| 字段候选 Precision | 1.000 |
| 字段候选 Recall | 0.750 |
| 未解析范围 | 无 |
| 聚类噪声消息 | 1 |

说明：本版本只展示由自动推断的长度关系支持的三类高置信结构边界（长度字段起点、载荷起点、尾部起点），因此候选总量明显减少，精确率提高。75% 的召回率说明仍有四分之一真实内部边界未作为高置信候选展示；这些指标不能证明字段名称、单位或语义被恢复，也不能外推到所有私有协议。

## 4. 结论

本次演示验证了项目能在不读取留出集协议真值的条件下，完成消息边界推断、消息类型划分和保守的字段候选排序；冻结验收和自动化回归均未出现失败项。

当前演示可对外表述为：**系统对该固定 UBX 留出集实现了可复核的边界、类型和字段候选推断，并输出哈希绑定的证据链。**

不应表述为“已经理解任意私有协议的字段语义”或“对所有未知协议保证同等准确率”。课程指定的隐藏 DAT/PCAP 若后续提供，仍需按同一命令链独立复测。

## 5. 可复核证据

- 冻结验收输入与结果：`data\acceptance\frozen-20260910\full-chain\acceptance.json`
- 验收器：`scripts\verify_acceptance.py`
- 全模块测试：`experiments\M01\tests` 至 `experiments\M12\tests`、`experiments\tests`
- UBX 留出集评估：`reports\unknown-private\wireshark-ubx-heldout-v1-ranked-v2\held_out_evaluation.json`
- 未知协议评估器：`scripts\evaluate_unknown_private_protocol.py`
- 字段候选实现：`experiments\M06\run.py`

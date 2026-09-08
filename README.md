# 网络加密流量二进制分析

面向课程设计技术探索题目的可解释分析原型：读取 `.dat/.bin/.pcap/.pcapng`，在不伪造缺失元数据的前提下，逐步完成字节特征、消息分帧、聚类、对齐、字段假设、标准协议解析、内容恢复、流量行为分析、分类与证据约束报告。

## 当前进度

- M01 输入与预处理：已有可运行实现。裸字节路径已在当前环境复测；抓包路径依赖 Wireshark CLI，当前机器未安装，因此相关测试明确跳过。历史上曾以 TShark 4.6.6 完成抓包、TCP 重组、重传与截断测试。
- M02 二进制基础特征：已有标准库实现与边界测试。
- M03 消息边界识别：长度字段、分隔符和固定长度规则基线已实现并通过带真值测试。
- M04 消息聚类：依赖标准库的 DBSCAN 基线已实现，支持组合距离、噪声、真实消息代表、轮廓系数，以及可选 ARI/NMI。
- M05 消息对齐：字节级 Needleman–Wunsch 参考对齐已实现，保留每个对齐单元到原消息的偏移，显式区分 gap 与 `0x00`。
- M06 字段与格式推断：按列统计、连续区域、边界候选及严格长度关系假设已实现，所有结论保留样本和原始偏移证据。
- M07–M12：已完成资料调研和初步选型，工程实现尚未开始。
- 真实课程 DAT：课程未提供；现已引入两个来源和许可明确的真实外部 DAT，并用 M01～M06 验证。它们能支撑开发，但不能代表课程隐藏验收数据。

权威状态见 `research/progress.md`，技术路线见 `research/selection.md`，课程原始要求见根目录 PDF。

多人协作时请先阅读 [`COLLABORATION.md`](COLLABORATION.md)，其中汇总了当前分支范围、模块接口、真实数据、复测命令、限制和后续分工入口。

## 快速运行

M01 对输入做内容探测，并在确认抓包后尝试提取包、流与双向 TCP 字节流：

```powershell
python experiments\M01\run.py data\fixtures\m01-raw.dat --output-dir tmp\m01-raw
```

M02 计算全局与滑动窗口字节特征：

```powershell
python experiments\M02\run.py data\fixtures\m01-raw.dat --output-dir tmp\m02-raw
```

M03 按显式、可解释规则切分连续字节流；完整参数见 `experiments/M03/README.md`：

```powershell
python experiments\M03\run.py stream.dat --output-dir tmp\m03-stream --rule fixed --frame-size 16
```

M04 对 M03 消息做可解释 DBSCAN 聚类；完整参数见 `experiments/M04/README.md`：

```powershell
python experiments\M04\run.py tmp\m03-stream\framing.json --output-dir tmp\m04-stream
```

M05 以 M04 的真实代表消息为锚进行簇内字节对齐；完整参数见 `experiments/M05/README.md`：

```powershell
python experiments\M05\run.py tmp\m04-stream\clusters.json --output-dir tmp\m05-stream
```

M06 从 M05 对齐列提出统计字段区间和长度关系假设；完整参数见 `experiments/M06/README.md`：

```powershell
python experiments\M06\run.py tmp\m05-stream\alignments.json --output-dir tmp\m06-stream
```

运行当前全部测试：

```powershell
python -m unittest discover -s experiments\M01\tests -v
python -m unittest discover -s experiments\M02\tests -v
python -m unittest discover -s experiments\M03\tests -v
python -m unittest discover -s experiments\M04\tests -v
python -m unittest discover -s experiments\M05\tests -v
python -m unittest discover -s experiments\M06\tests -v
python -m unittest discover -s experiments\tests -v
```

各模块 CLI 均拒绝覆盖已存在的输出目录。临时结果放在 `tmp/`，该目录不会进入 Git。

## 核心原则

- `.dat` 只是扩展名，格式判断来自内容和结构证据。
- TCP 分段边界不等于应用消息边界；Packet、Flow、Stream、Message、Field 分层建模。
- 缺少方向、时间戳、包边界或标签时显式报告缺失，不从字节偏移推造。
- 高熵不等于加密；编码、压缩、随机数据和密文必须保留多种可能。
- 所有推断保留来源、参数、偏移与限制，LLM 只能解释证据，不能替代解析证据。

## 后续里程碑

1. 结合 M06 结果继续完成 M07 标准协议识别和 M08 可见内容恢复；未知私有协议字段语义仍需更多样本验证。
2. 恢复 Wireshark/TShark 环境并完成 M01/M07/M08 抓包路径复测。
3. 完成 M09/M10 流量统计与可解释行为规则；取得有标签数据后再做 M11。
4. 用模板报告先完成 M12，再把可选 LLM 接入限制在证据解释层。
5. 用课程真实 DAT 做最终适配，补齐设计报告、测试报告、安装使用文档、PPT 与演示材料。

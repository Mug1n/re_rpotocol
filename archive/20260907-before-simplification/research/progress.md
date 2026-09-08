# 调研进度

最后更新：2026-09-07

状态定义：`not_started`、`searching`、`comparing`、`running`、`completed`、`blocked`。

| 模块 | 任务 | 状态 | 关键证据 | 阻塞项 | 下一步 |
|---|---|---|---|---|---|
| M1 | 数据输入与预处理 | blocked | `research/M01-input/dat-input-contract.md`；`research/M01-input/report.md`；`experiments/M01/runs/20260907-m01-smoke/` | 当前目录不是 Git 检出，尚未获准初始化；另缺少真实 DAT | 获准后初始化 Git、创建分支并实现 DAT 优先适配器与 E4 测试 |
| M2 | 二进制基础特征分析 | not_started | - | - | 按执行顺序进入本模块 |
| M3 | 消息边界识别 / Framing | not_started | - | - | 按执行顺序进入本模块 |
| M4 | 消息聚类 | not_started | - | - | 按执行顺序进入本模块 |
| M5 | 消息对齐 | not_started | - | - | 按执行顺序进入本模块 |
| M6 | 字段边界 / 协议格式推断 | not_started | - | - | 按执行顺序进入本模块 |
| M7 | 标准协议识别与解析 | not_started | - | - | 按执行顺序进入本模块 |
| M8 | 明文提取与数据恢复 | not_started | - | - | 按执行顺序进入本模块 |
| M9 | 流量统计特征 | not_started | - | - | 按执行顺序进入本模块 |
| M10 | 数据访问行为分析 | not_started | - | - | 按执行顺序进入本模块 |
| M11 | 数据访问行为类型分类 | not_started | - | - | 按执行顺序进入本模块 |
| M12 | LLM 语义分析与报告 | not_started | - | - | 按执行顺序进入本模块 |

## 当前阶段

- 已完成项目文件盘点和调研目录初始化。
- M1 已完成首轮权威来源核验、四候选实测、正常/多流/乱序重复/截断/裸字节/伪 magic fixture、DAT 输入契约、JSON Schema 与初步选型。
- 尚未收到用户待分析的 `.dat`、`.bin`、`.pcap` 或 `.pcapng` 数据。
- M1 的非代码调研证据已尽可能补齐；统一 CLI 和 E4 因当前目录不是 Git 检出而阻塞。
- 获得 Git 初始化授权后继续实现 M1，完成后再进入 M2。

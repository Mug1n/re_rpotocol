# M11 业务分类的真实加密流量外部评测（ISCX VPN-nonVPN 2016）

本文件记录 M11“条件行为分类”在**外部真实加密流量**上的一次离线评测：数据来源、评测协议、结果和限制。上游计划见 [research/M11-behavior-classification/report.md](../research/M11-behavior-classification/report.md) 第 15 行——该报告明确要求“分别定义和评测业务分类与 VPN 状态分类”。本文只覆盖其中的**业务分类（`task=application`）**维度。

结果与来源证据以机器可读形式保存在 [data/external/iscx-vpn-2016/](../data/external/iscx-vpn-2016/)，原始抓包不进入 Git。

## 1. 结论

| 指标 | 值 |
|---|---:|
| 2 折会话不交叠 macro-F1 均值 | **0.4995** |
| 多数类基线均值 | 0.3040 |
| 相对多数类提升 | **+0.1955** |
| 评测 flow（=特征行）总数 | 1028 |
| 类别数 / 抓包会话数 | 5 / 28（自 31 个候选中） |

这是 M11 目前唯一一个**标签与数据都不来自本项目自身构造**的泛化数字。它高于多数类基线，但离可用分类器仍有明显距离——`voip` 与 `ft` 两类的 F1 仅约 0.25–0.27，错误主要集中在 `voip→streaming` 与 `ft→chat` 的方向上。

## 2. 数据来源

| 项 | 值 |
|---|---|
| 数据集 | ISCX VPN-nonVPN 2016（UNB CIC），真实 OpenVPN 加密业务流量 |
| 官方入口 | <https://www.unb.ca/cic/datasets/vpn.html> |
| 实际获取地址 | `https://www.kaggle.com/api/v1/datasets/download/mitu1957264/iscx-vpn` |
| 获取方式 | 匿名 HTTPS 下载数据集归档（无需账号），`curl -L` |
| 归档 sha256 | `63efacb7a221479f…`（完整值见 manifest.json） |
| 归档大小 | 2,336,592,297 字节 |
| 获取日期 | 2026-09-11 |

官方 UNB 下载链接已失效：访问时 301 重定向到数据集索引页，不再提供归档。实际字节来自上表的 Kaggle 镜像，因此**归档哈希是绑定的，但镜像与 UNB 原始发布之间的一致性未经独立核实**。每个会话的源抓包与截断后抓包哈希均记录在 `manifest.json`。

抓包不进入 Git（约 2.4 GB），可凭上表 URL 重新获取并按哈希核对。

## 3. 标签映射

数据集按抓包文件名表达业务类别。本项目按文件名 token 映射到 5 类，映射规则写在 `manifest.json` 的 `sessions[].label_basis` 中：

| 文件名 token | 本评测类别 |
|---|---|
| `aim_chat` / `facebook_chat` / `hangouts_chat` / `icq_chat` / `skype_chat` | `chat` |
| `email` | `mail` |
| `ftps` / `sftp` / `skype_files` | `ft` |
| `netflix` / `spotify` / `vimeo` / `youtube` | `streaming` |
| `facebook_audio` / `hangouts_audio` / `skype_audio` / `voipbuster` | `voip` |
| `bittorrent` | `p2p`（未参与评测，见 §4） |

标签依据是数据集发布的抓包命名约定，**不是逐 flow 的人工确认**。这是外部标签，但不是独立标注真值。

## 4. 评测协议

M11 只接受含固定维数值特征、明确标签维度和互斥 `group_id` 的输入；`group_id` 用于保证分组不跨越训练与评估边界。协议如下：

- **分组**：`group_id = 抓包文件名`。同一次抓包的所有 flow 只会完整落在训练侧或测试侧，杜绝同会话泄漏。
- **切分**：`explicit_partition`，两折互补。每类会话按名称排序后，奇数索引进测试为 `f1`，偶数索引进测试为 `f2`。这样每个参与评测的类都同时出现在两折的两侧。
- **类别保留条件**：类内会话数 ≥ 2，否则无法做分组不交叠留出。
- **特征**：M09 → `build_rows.py` 的 17 维固定特征集（`feature_definition_version = "0.2"`），特征由单条 flow 的包长、方向、间隔、突发与重传统计派生，不含标签信息。
- **模型**：M11 默认 RandomForest 基线，`class_weight="balanced"`，参数未针对本数据集调优。
- **采集截断**：为控制 M01 单包产物规模，每个抓包用 `tshark -c 20000` 截断到前 20000 个包后再分析。28 个参与评测的会话中 16 个被截断。

## 5. 结果

### 5.1 两折总体

| 折 | 测试会话 | 测试行 | macro-F1 | 多数类基线 | 准确率 |
|---|---:|---:|---:|---:|---:|
| f1 | 13 | 411 | 0.4722 | 0.2822 | 0.4672 |
| f2 | 15 | 617 | 0.5268 | 0.3258 | 0.5024 |
| **均值** | — | 1028 | **0.4995** | 0.3040 | — |

### 5.2 分类别 F1

| 类别 | 会话数 | 行数 | F1 (f1) | F1 (f2) |
|---|---:|---:|---:|---:|
| chat | 10 | 190 | 0.481 | 0.561 |
| ft | 6 | 199 | 0.275 | 0.520 |
| mail | 2 | 143 | 0.876 | 0.815 |
| streaming | 5 | 217 | 0.456 | 0.494 |
| voip | 5 | 279 | 0.272 | 0.243 |

`mail` 稳定最好（F1 ≈ 0.85），`voip` 两折都最差（≈ 0.25）。`ft` 两折方差最大（0.275 → 0.520），与它只有 6 个会话、且错分方向依赖测试折里恰好是哪种传输有关。

### 5.3 主要错误方向（f1 混淆矩阵，行=真实）

| 真实\预测 | chat | ft | mail | streaming | voip |
|---|---:|---:|---:|---:|---:|
| chat | 45 | 0 | 1 | 0 | 12 |
| ft | **49** | 23 | 1 | 35 | 8 |
| mail | 12 | 3 | 60 | 0 | 0 |
| streaming | 7 | 20 | 0 | 47 | 10 |
| voip | 16 | 5 | 0 | **40** | 17 |

两类系统性错分：`ft` 有 49/116 被判成 `chat`；`voip` 有 40/78 被判成 `streaming`。两者都是**对称型、低负载、长持续**的流形态，在纯统计特征上高度重叠。完整混淆矩阵见 `evaluation.json`。

## 6. 限制

以下限制决定了这个数字只能作参考，不能当作产品指标：

1. **截断改变流量形状**。10000–20000 包上限把长会话截短，`duration_seconds`、`byte_count` 等特征被系统性压低，部分应用阶段（如流媒体起播后的稳态）可能整个被切掉。16/28 个会话受影响。
2. **`mail` 只有 2 个会话**。两折各留出 1 个会话，因此 `mail` 的高 F1 实际上是“对单个未见会话”的泛化，方差不可估计。
3. **只评测了 VPN 抓包**。本次只下载并使用了 `vpn_*` 系列，因此上游报告要求的“VPN 状态分类”维度**没有评测**；也没有非 VPN 对照。
4. **参数未调优**。使用的是 M11 默认基线，没有做特征选择、超参搜索或阈值调优。当前 `reject_threshold` 默认为 0.5，本评测未做拒识分析。
5. **标签来自文件名约定**，非逐 flow 人工标注。
6. **官方链接失效，字节来自社区镜像**，镜像保真度未独立核实。

## 7. 复跑命令

前置：本机 Wireshark（提供 `tshark` / `capinfos`），以及 `scikit-learn`、`joblib`。

```powershell
# 1) 获取归档并解出抓包（2026-09-11 实测可用；需网络）
curl -L -o tmp\kaggle\iscx-vpn-2g.zip https://www.kaggle.com/api/v1/datasets/download/mitu1957264/iscx-vpn
#    解压到 tmp\kaggle\iscx-vpn\*.pcap，并与 manifest.json 的 sha256 核对

# 2) 逐会话跑 M01 -> M09，生成 flow 特征（每个抓包先截断到 20000 包）
python -B tmp\iscx-work\run_pipeline.py

# 3) 合并带标签行、按会话 2 折互补切分、两折各跑一次 M11
python -B tmp\iscx-work\train_m11.py

# 4) 从临时输出重新生成被追踪的证据文件
python -B tmp\iscx-work\emit_artifact.py
```

`tmp/` 不进入 Git，上述三个驱动脚本是本次评测的临时工具；`emit_artifact.py` 会把 `tmp/iscx-work/` 的结果收敛成 `data/external/iscx-vpn-2016/` 下可追踪的 `manifest.json` 与 `evaluation.json`。

## 8. 与本地冻结闭环的关系

本评测**不替代**验收闭环里的 M11 证据。`data/acceptance/frozen-20260910/` 的 M11 产物和 `reports/acceptance/2026-09-11-abc/` 的验收记录描述的是端到端流水线在冻结输入上的可复现性；本文描述的是同一 M11 代码在外部真实流量上的泛化表现。两者回答的是不同问题，请勿交叉引用。

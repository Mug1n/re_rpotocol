# M07～M12 模块接口契约

更新日期：2026-09-08

本文档规定剩余分析模块的集成边界。各模块在 `research/Mxx-*` 下实现的 JSON Schema 是机器校验权威；本文档与 Schema 不一致时，必须在同一次变更中同步更新，并以 Schema 的校验行为为准。

## 1. 通用原则

- 每个模块在新输出目录中写入一份主 JSON 结果，并拒绝覆盖已有目录。
- 每份结果必须记录上游 artifact 的路径和 SHA-256；消费者处理前必须校验哈希。
- 结果中的输入路径优先相对于结果文件解析；artifact 移动后允许通过 CLI 显式覆盖路径，但不能绕过哈希校验。
- 字节位置统一使用从 0 开始的半开区间 `[start, end)`；时长统一使用秒，字节数和包数必须明确口径。
- 不得补造未知事实。缺失值应省略，或写为 `null` 并同时给出机器可读原因。
- 输入非法、Schema 失败或源哈希不匹配时，必须在最终输出目录落盘前失败；可选证据缺失时，写出带降级状态的合法结果。
- 无语义顺序的数组按稳定 ID 排序；数值结果不得出现 NaN 或无穷大。
- `warnings` 只承载面向人的说明；程序分支依据 `status`、可用性字段和原因码，不能解析警告文本。

## 2. 通用结果封装

M07～M12 延续 M04～M06 的顶层结构：

| 字段 | 必填 | 约定 |
|---|---:|---|
| `schema_version` | 是 | 初始为 `0.1`；不兼容变更必须升级版本。 |
| `source` | 是 | 上游路径、SHA-256、ID、数量及可选来源模块版本。 |
| `status` | 是 | 采用各模块枚举，表示证据完整性，不表示执行进度。 |
| `parameters` | 是 | 记录所有会改变结果的阈值、解码模式、工具选项和安全上限。 |
| `metrics` | 是 | 数量和质量摘要；空结果也提供安全的零值或 `null`。 |
| `warnings` | 是 | 字符串数组；无警告时为空。 |

通用来源引用包含 `module`、`artifact_path`、`artifact_sha256`、可选 `record_id` 和 `schema_version`。`artifact_sha256` 必须是上游 JSON 或二进制 artifact 精确字节的 64 位小写 SHA-256。

## 3. M01 契约收紧

M07 和 M09 均消费 `research/M01-input/input-artifact.schema.json`。两者集成前，应把当前未约束的 `packets`、`flows`、`streams` 元素改为显式 `$defs`，并兼容 M01 已经生成的记录。

### 3.1 包记录

必填字段：`id`、`source_id`、`index`、`timestamp_epoch`、`interface_id`、`captured_length`、`original_length`、`truncated`、`source_file_offset`、`source_offset_reason`、`tcp_stream`、`src_ip`、`src_port`、`dst_ip`、`dst_port`、`tcp_seq_raw`、`tcp_payload_length`、`payload_ref`、`analysis`。

- TShark 无法提供的抓包字段允许为 `null`。
- `timestamp_epoch` 保持十进制字符串，避免浮点精度损失。
- `analysis` 必须包含 `retransmission`、`out_of_order`、`gap_or_loss`。
- `source_file_offset` 为 `null` 时，`source_offset_reason` 必须非空。

### 3.2 流记录

必填字段：`id`、`source_id`、`transport`、`tcp_stream`、`node0`、`node1`、`packet_ids`、`first_timestamp_epoch`、`last_timestamp_epoch`。

未提供经验证的角色映射时，端点只能称为 `node0`、`node1`，不得静默改称客户端/服务端或上传/下载。`packet_ids` 必须引用同一 M01 artifact 中存在的包。

### 3.3 重组字节流记录

必填字段：`id`、`source_id`、`flow_id`、`tcp_stream`、`node0`、`node1`、`packet_ids`、`directions`、`analysis`、`reassembly_status`。

- 方向枚举：`node0_to_node1`、`node1_to_node0`。
- 每个方向记录 `length`、`sha256`、`artifact_ref`。
- `reassembly_status` 区分 `complete` 与 `partial`；`partial` 必须由警告和包分析解释。

## 4. M07 标准协议识别

主输出：`protocols.json`

Schema：`research/M07-standard-protocols/protocols.schema.json`

### 输入与状态

- 必需：M01 `result.json` 及原始抓包。
- 可选：Decode As、显示过滤器、启用协议配置和用户明确提供的解密材料。
- 裸字节且没有已声明应用流格式时返回 `not_applicable`，不得伪造网络头。
- 状态：`ok`、`partial`、`unknown`、`not_applicable`、`tool_unavailable`。

### 输出字段

| 字段 | 约定 |
|---|---|
| `tool` | TShark 路径、版本及影响结果的配置；不得记录密钥内容。 |
| `observations` | 关联包、流或字节流 ID 的协议观测。 |
| `unknown_scopes` | 尝试识别但未确认的范围和原因码。 |
| `artifacts` | 可选 TShark JSON/导出对象引用、长度和 SHA-256。 |

每条观测包含 `observation_id`、`scope_type`、`scope_id`、`protocol`、`recognition_mode`、`visibility`、`field_evidence`、`limitations`。`recognition_mode` 为 `dissector`、`heuristic` 或 `decode_as`；`visibility` 为 `metadata_only`、`partial_payload` 或 `application_visible`。端口号不能单独构成已确认协议结论。

## 5. M08 内容恢复

主输出：`recovery.json`

Schema：`research/M08-recovery/recovery.schema.json`

### 输入与状态

- 至少一个含字节的来源：M01 原始/重组数据、M03 消息，或 M07 导出的协议载荷/对象。
- 可选协议结果可以提供已声明内容类型、编码和压缩证据。
- 状态：`ok`、`partial`、`empty`、`no_recoverable_content`。

### 输出字段

| 字段 | 约定 |
|---|---|
| `recoveries` | 产生受限输出的已确认或候选转换。 |
| `failed_attempts` | 带稳定原因码且未生成 artifact 的失败尝试。 |
| `skipped_sources` | 因加密、不完整、超限或不支持而跳过的来源。 |

每项恢复包含 `recovery_id`、`source_ref`、`source_range`、`basis`、`transformation_chain`、`output`、`completeness`、`evidence`。

- `basis`：`protocol_declared`、`validated_magic`、`strict_candidate`。
- 转换步骤记录操作、输入/输出长度、可公开参数和校验结果。
- 输出记录 `artifact_ref`、`sha256`、`length`，以及可选媒体类型和文本编码。
- `completeness`：`complete`、`partial`、`candidate`；解码成功本身不能证明业务语义。
- 参数必须包含最大递归层数、最大输出字节、最大膨胀比例、最短可打印片段和启用的解码器。

## 6. M09 流量特征

主输出：`flow_features.json`

Schema：`research/M09-flow-features/flow-features.schema.json`

### 输入与状态

- 必需：包含包和流记录的 M01 `result.json`。
- 包数量和长度分布需要包边界；时序特征需要时间戳；方向保持 node 相对，除非提供经验证的角色映射。
- 状态：`ok`、`partial`、`empty`、`insufficient_metadata`。

### 输出字段

| 字段 | 约定 |
|---|---|
| `feature_definition` | 长度口径、重传策略、分位数方法、突发阈值和角色映射模式。 |
| `flows` | 每个 M01 流对应一条特征记录。 |
| `unavailable_features` | 不可计算的特征、受影响流和原因码。 |

每条流记录包含身份、总量和分方向计数、包长统计、持续时间和包间隔、速率、方向切换、node 相对比例、突发摘要，以及截断/重传/乱序/丢失计数。生产者必须先校验 M01 Schema 和内部引用，并拒绝非有限时间戳或参数；不得使用 M03 消息长度冒充网络包长度。

## 7. M10 行为分析

主输出：`behaviors.json`

Schema：`research/M10-behavior-analysis/behaviors.schema.json`

### 输入与状态

- 必需：M09 `flow_features.json`；周期性分析可额外接收分桶时间序列。
- 状态：`ok`、`partial`、`empty`、`insufficient_evidence`。

### 输出字段

`rule_set` 记录规则版本和阈值；`observations` 记录每个流零条或多条非互斥观测；`insufficient_scopes` 记录无法支撑某条规则的流及缺失证据。消费者必须验证 M09 Schema，并重新核对 M09 声明的 M01 artifact 哈希。

首版类型为 `periodicity_candidate`、`direction_dominance`、`bursty_transfer`、`long_lived_intermittent`。每条观测包含 `behavior_id`、`flow_id`、`type`、`observed_values`、`thresholds`、`evidence_refs`、`confidence_basis`、`limitations`，只能描述统计模式，不得声称应用、意图或恶意性。

## 8. M11 行为分类

主输出：`classification.json`；只有训练成功后才另外写 `model.joblib`，其 artifact 清单内嵌在主输出中。

Schema：`research/M11-behavior-classification/classification.schema.json`

### 输入与状态

- 与 M09 兼容的固定维度特征行。
- 只包含一个命名任务维度的显式标签，以及防泄漏划分所需的组 ID。
- 状态：`ok`、`evaluation_only`、`insufficient_labels`、`dependency_unavailable`、`empty`。

### 输出字段

| 字段 | 约定 |
|---|---|
| `task` | 标签维度、类别集合、未知/拒识策略和特征 Schema 版本。 |
| `split` | 分组键、训练/测试数量、各分区组 ID、空交集证明和随机种子。 |
| `model` | 算法、参数、依赖版本，以及模型引用和 SHA-256。 |
| `metrics` | macro-F1、逐类指标、support、混淆矩阵和可选校准指标。 |
| `predictions` | 范围 ID、预测标签、分数类型/值和拒识状态。 |
| `leakage_checks` | 证明预处理只在训练集拟合，且组不跨数据分区。 |

M04 簇 ID 永远不能作为行为标签；应用类别与 VPN 状态必须是两个独立任务。所有特征必须为固定列的有限数值，训练和测试分区必须各自包含全部类别。标签或可行分组不足时输出 `insufficient_labels`，不得给出准确率结论；成功训练必须原子发布 `model.joblib` 并在 `classification.json` 中记录长度和 SHA-256。

## 9. M12 证据与报告

主输出：`report.md`、`report_manifest.json`。

Schema：`research/M12-llm/evidence.schema.json`、`research/M12-llm/report-manifest.schema.json`

### 输入

任意经过校验的 M01～M11 结果。M03～M06 的消息、未解析区间、簇/噪声、对齐/未对齐消息、字段、边界与长度关系候选必须保留为记录级证据，而非只输出模块状态。确定性报告器必须在没有模型端点时工作。

### 证据记录

每条规范化证据包含 `evidence_id`、`module`、`source_ref`、`scope`、可选 `location`、`observation`、`method`、`limitations`。`source_ref` 必须保留 artifact 路径、SHA-256 和可选记录 ID。

### 报告清单

manifest 记录所有已校验输入及哈希、各章节证据 ID、生成模式、截断决策、警告和报告 SHA-256。Markdown 报告分为“观测事实”“解释与假设”“无法判断”“后续建议”。

可选 LLM 文本只能基于规范化证据生成，必须标记为模型生成并引用存在的证据 ID；引用不能支持陈述时应拒绝或降级。模型失败不能阻止确定性报告生成。

## 10. 兼容性与所有权

| 生产者 | 主要消费者 | 兼容性门槛 |
|---|---|---|
| M01 | M07、M09 | 详细 packet/flow/stream Schema 校验通过且源哈希一致。 |
| M03/M07 | M08 | 字节 artifact 存在，长度/哈希一致，来源区间可解析。 |
| M09 | M10、M11 | 特征定义版本一致，所需特征可用。 |
| M01～M11 | M12 | 输入 Schema 校验通过，适配器保留来源 ID 和限制。 |

- 开发者 A 负责 M07、M08、M12 的 Schema 与适配器。
- 开发者 B 负责 M09、M10、M11 的 Schema 与适配器。
- M01 契约收紧和本文档必须由两人共同审核。
- 任何不兼容的生产者变更，都必须在同一次集成变更中更新消费者、fixture、Schema 和兼容矩阵。

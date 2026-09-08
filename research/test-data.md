# 测试数据调研与建议

状态：第一轮候选检索完成。检索日期：2026-09-08；尚未下载外部数据，也未运行候选工具。

## 结论

不建议寻找一个覆盖全部模块的“万能数据集”。本项目至少需要三类相互独立的真值：

1. **协议与字段真值**：用于 M3～M8，要求消息内容可见，最好有正式协议规范或 Wireshark dissector 可交叉验证。
2. **时间、方向与行为标签**：用于 M9～M11，要求保留 PCAP 元数据，并明确标签是在包、流、连接还是采集任务层面生成。
3. **输入异常与缺失信息**：用于 M1～M3 的鲁棒性测试，包括伪扩展名、截断、损坏头、裸流和多流混合。这部分应从可信原始数据确定性派生，并记录变换过程。

第一批最有实践价值的组合是：**NetPlier 小型 PCAP + BinaryInferno 消息集 + 精选 Wireshark SampleCaptures**。三者体量小、来源与预期结果较清楚，可以先形成可重复的 M1～M8 协议处理链回归集。行为分类另用 **MIT Lincoln Laboratory VNAT 的 8.6 MB 特征文件**做 M9～M11 管线冒烟测试；只有需要验证自有 M9 特征提取时，再获取其 1.05 GB 时序数据或 36.1 GB 原始 PCAP。

## 候选数据源

| 优先级 | 数据源 | 可用内容与真值 | 适合模块 | 实践价值 | 主要限制 |
|---|---|---|---|---|---|
| P0 | [NetPlier 数据目录](https://github.com/yapengye/NetPlier/tree/master/data)及[论文](https://www.ndss-symposium.org/ndss-paper/netplier-probabilistic-network-protocol-reverse-engineering-from-message-traces/) | 仓库直接提供 9 个各含 100 条样本的 PCAP：DHCP、DNP3、ICMP、Modbus、NTP、SMB、SMB2、TFTP、ZeroAccess；README 记录了原始公开 trace、过滤条件及 TShark 真值类型 | M1、M2、M4～M7、M9 | 小而多样，覆盖普通网络、工业控制、文件服务与恶意流量；论文工具与数据同仓库，最适合作为首批回归基准 | 这些是过滤后的消息集，不代表真实部署分布；仓库为 GPL-3.0，但各上游 trace 的数据许可仍需逐项核对；TShark 生成的真值需固定版本和字段口径 |
| P0 | [BinaryInferno 数据目录](https://github.com/binaryinferno/binaryinferno/tree/main/dataset)及[NDSS 2023 论文](https://www.ndss-symposium.org/ndss-paper/binaryinferno-a-semantic-driven-approach-to-field-inference-for-binary-message-formats/) | 仓库提供一行一条 Hex 消息的 payload/top-level 数据，并按 100、500、1000 样本量组织；论文基准包含 BGP、DHCP、NTP、SMB/SMB2、DNP3、Modbus、MAVLink、Mirai 和教程协议 | M2、M4、M5、M6 | 可直接测试变长二进制消息、样本规模效应和字段推断，不必先处理 PCAP；论文给出与多种 PRE 方法的同集比较 | 不保留包时间、方向和会话，不能测试 M1 抓包分支或 M9～M11；仓库内数据说明很简略，字段真值主要来自论文、协议规范或 dissector，落库前需另做机器可读标注；仓库为 GPL-3.0 |
| P0 | [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures)及[Wireshark 测试 captures](https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures) | 大量按协议说明的 PCAP/PCAPNG，以及 Wireshark 自身回归测试用抓包；可选 `http.cap`、`http_gzip.cap`、`http-chunked-gzip.pcap`、`http_with_jpegs.cap.gz`、`smtp.pcap`、`dns_port.pcap`、`dhcp.pcapng`、`pcapng-example.pcapng` 等 | M1、M3、M7、M8，兼顾 M9 | 最适合验证标准协议识别、非标准端口、TCP 分段/重组、gzip 解压、对象恢复及复杂 PCAPNG 元数据 | Wiki 是样例集合，不是统一标注的数据集；每个文件质量、隐私处理与许可可能不同，必须逐文件记录来源和使用条件 |
| P1 | Wireshark 带密钥样例（位于同一 [SampleCaptures](https://wiki.wireshark.org/SampleCaptures#ssl-with-decryption-keys) 页面） | `snakeoil2_070531.tgz` 含 HTTPS 与解密密钥；`smtp-ssl.pcapng`、`pop-ssl.pcapng`、`imap-ssl.pcapng` 等把 TLS 密钥写在 capture comments 中；另有非标准端口的 `smtp2525-ssl.pcapng` | M7、M8 | 可以成对验证“无密钥只能看握手/记录”与“有密钥可恢复应用层”的边界，是课程展示价值很高的正反例 | 老版本 TLS/SSL 样本不能代表现代 TLS 全貌；密钥材料必须仅作为测试资产保存，不混入真实凭据；逐文件许可待核实 |
| P1 | [MIT Lincoln Laboratory VNAT](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat)及关联论文 | 36.1 GB 原始 PCAP，33,711 个连接、约 272 小时；另有 1.05 GB 的包时间/大小/方向 HDF5 与 8.6 MB 的预计算特征 HDF5。覆盖 VPN/非 VPN 的流媒体、VoIP、聊天、C2、文件传输等类别 | M9、M10、M11 | 官方页面同时给原始抓包、中间时序和特征，适合分别验证特征提取、行为描述和分类；隔离子网采集使标签来源相对清楚 | 原始集较大；应用/采集环境仍有领域偏移；文件名携带标签，划分不当会造成泄漏；官方页面未明确给出可再分发许可，下载前需核实条款 |
| P1 | [UNB ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html)及[ICISSP 2016 论文](https://www.scitepress.org/Papers/2016/57407/) | 官方页面说明提供完整 PCAP 与 ISCXFlowMeter CSV，覆盖浏览、邮件、聊天、流媒体、文件传输、VoIP、P2P，并区分 VPN/非 VPN | M9、M10、M11 | 与现有 M11 选型报告一致，文献引用多，适合作为经典可比基线 | 数据较旧，应用版本与当代流量不同；VPN/非 VPN 与业务类别是两个标签维度，不能混成一个任务；下载及研究引用条件需遵守 |
| P2 | [l2pre 的 iPCF 样例](https://github.com/techge/l2pre) | `input/iPCF` 提供 PCAPNG 与 YAML 上下文，仓库示例展示帧类型、MAC、序列、channel、checksum 等字段及导出协议格式/Boofuzz/Wireshark dissector 的流程 | M1、M4～M6，扩展到链路层 | “抓包 + 外部上下文”比只靠 dissector 更接近真实逆向工作，可用于验证上下文关联字段和校验字段 | 项目已于 2026-02-13 归档，只读；样例范围较窄，不能作为主基准；仓库 MIT 许可，但仍需确认样例数据是否完全随仓库许可发布 |

## 不作为首批数据源的项目

- [NEMESYS/NEMETYL](https://github.com/vs-uulm/nemesys)值得用于 M6 的算法比较和 Format Match Score（FMS）评测。仓库文档要求用户向脚本提供 PCAP，并说明可用 TShark dissector 生成真实字段对照；当前没有证据表明仓库自带一套可直接采用的完整 PCAP 基准，因此不把它列为数据集。可让它读取 NetPlier 或 Wireshark 样本。
- 超大综合安全数据集不适合首轮。若只有攻击/正常标签而没有应用消息和字段真值，它们对 M3～M8 的帮助很小；直接下载还会增加存储、清洗和隐私审计成本。
- Kaggle 上的二次整理版不作为权威源。即使下载更方便，也可能改变列、标签、过滤规则或许可；优先从作者、大学或论文仓库获取原始版本。

## 建议的首批测试包

### A. 小型协议逆向基准

从 NetPlier 获取全部 9 个 `*_100.pcap`。每个协议再确定性抽取 10、30、100 条消息三个规模层级：

- 10 条：CLI 与格式冒烟测试；
- 30 条：快速回归；
- 100 条：默认基准；
- BinaryInferno 的 500/1000 条版本仅用于规模与稳定性测试。

这一批先覆盖不同结构：定长/近定长（ICMP、NTP）、TLV/选项型（DHCP）、工业协议（DNP3、Modbus）、复杂变长协议（SMB/SMB2）、简单操作码与字符串（TFTP），以及恶意协议样本（ZeroAccess）。恶意 PCAP 只做离线解析，禁止回放、执行 payload 或连接其中地址。

### B. 标准协议与恢复基准

从 Wireshark 精选以下小文件，而不是整库下载：

- 输入与封装：`pcapng-example.pcapng`、`dhcp.pcapng`；
- 非标准端口：`dns_port.pcap`、`smtp2525-ssl.pcapng`；
- TCP 重组：`tcp-ethereal-file1.trace` 或 `mysql-ssl-larger.pcapng`；
- 明文/压缩/对象恢复：`http.cap`、`http_gzip.cap`、`http-chunked-gzip.pcap`、`http_with_jpegs.cap.gz`；
- 加密边界：`snakeoil2_070531.tgz`，分别在不加载和加载测试密钥时运行。

### C. 行为分类基准

先获取 VNAT 的 8.6 MB feature HDF5，只验证 M11 数据加载、分组划分、训练与报告接口。然后按需要升级：

1. 1.05 GB 时序 HDF5：验证 M9/M10 的包长、方向、IAT、突发与周期特征；
2. 36.1 GB PCAP：只在需要端到端复算特征时获取；
3. ISCXVPN2016：作为跨数据集或经典基线，不与 VNAT 随机混合后再切分。

## 从原始数据派生 DAT 的方法

课程最终输入是 DAT，但扩展名不代表格式。应从同一份已知 PCAP 生成成对样本，并把变换写入 manifest：

| 派生类型 | 生成方式 | 主要验证点 |
|---|---|---|
| `capture-as-dat` | 原 PCAP/PCAPNG 内容逐字节复制，仅改扩展名 | M1 内容识别不能依赖扩展名 |
| `payload-as-dat` | 按指定包/层抽取 payload，保留源包号和偏移 | 裸字节的 M2/M6 分支；不得伪造时间和方向 |
| `stream-as-dat` | 按五元组和方向重组 TCP 字节流 | M3 连续流分帧；不能把 TCP 段边界当消息边界 |
| `truncated` | 在记录的确定偏移截断容器、包、消息或压缩流 | 残片、校验失败和错误报告 |
| `concatenated` | 按记录顺序拼接多条完整消息，必要时加入未知尾部 | 多消息边界、尾部残片与多假设输出 |
| `negative-bytes` | 使用固定随机种子生成随机 bytes，并另生成 gzip/zlib、Base64、Hex 正负例 | 区分高熵、压缩、编码和密文；禁止把“能解码”当成协议真值 |

不要覆盖或修改下载的原始文件；所有派生文件保存 `source_sha256`、变换参数、工具版本和自身 `sha256`。

## 数据管理与评测最佳实践

建议为每个资产记录以下最小 manifest 字段：

```text
dataset_id, artifact_id, source_url, retrieved_at, license_or_terms,
sha256, byte_size, container, link_type, protocol, protocol_version,
capture_scope, message_count, timestamp_available, direction_available,
label_level, ground_truth_source, sensitive_content, allowed_use,
derivation, parent_artifact_id, split_group
```

测试时采用以下规则：

1. **冻结原始层**：`data/external/raw/` 只读；派生数据放 `data/derived/`，期望结果放 `data/ground-truth/`。
2. **固定工具版本**：特别记录 TShark/Wireshark 版本、启用的重组设置、Decode As 和解密配置。dissector 输出是可复现的参考真值，不是永恒不变的绝对真值。
3. **按会话/文件/主机分组切分**：同一 capture、同一脚本生成批次或相邻连接不能跨 train/test；VNAT 文件名和路径中的标签也不能作为特征。
4. **分开闭集与开放集**：M11 先做已知类别闭集分类，再用完全未见协议/应用测试拒识；不能把低置信度强制命名为某类别。
5. **分别报告每层指标**：M1 格式识别与错误分类；M3 边界 precision/recall/F1；M4 ARI/NMI 及噪声率；M6 字段边界 precision/recall/FMS；M7 协议/字段一致性；M8 恢复字节哈希与完整性；M9 数值误差；M10 规则触发证据；M11 macro-F1、每类召回、混淆矩阵和分组外测试。
6. **保留难例与负例**：非标准端口、跨 TCP 段、截断、压缩、加密、错误扩展名和缺失元数据都应有明确预期，避免只验证理想样本。

## 下一步

在不下载大数据集的前提下，下一轮可先完成：

1. 建立 `data/external/manifest.json` 的正式 schema；
2. 获取并校验 NetPlier 9 个小型 PCAP、BinaryInferno 的 100-message 子集和上述 Wireshark 精选文件；
3. 用 TShark 与协议规范生成第一版机器可读真值；
4. 从这些原始文件生成成对 DAT/截断/裸流样本；
5. 再根据磁盘预算和 M9～M11 的开发进度决定是否获取 VNAT 中型或完整版本。

下载前需要先核实每个来源的再分发条款；不能仅凭代码仓库许可证推定其中所有第三方抓包也采用同一许可证。

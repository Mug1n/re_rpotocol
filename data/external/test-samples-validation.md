# 公共协议测试包验证记录

验证日期：2026-09-09。文件、固定上游版本、SHA-256 和许可边界见 `test-samples-manifest.json`。

## 覆盖范围

- 常见协议：DHCP、ICMP、NTP、SMB/SMB2、TFTP、DNS、HTTP、BGP。
- 工业与少见协议：DNP3、Modbus/TCP、OPC UA、DTN BPv7/TCPCLv4、MAVLink。
- 自定义或论文消息：BinaryInferno tutorial 格式、Protocol Buffers 测试协议。
- 恶意或未知协议：ZeroAccess、Mirai。仅允许离线解析，禁止回放、执行载荷或连接捕获地址。
- 负例：变长随机消息和定长随机消息，用于检查高熵数据不会被伪解释为协议字段。

## 本地验证结果

NetPlier 和 Wireshark 的 15 个抓包均通过 M01 的容器结构检查，并由本机 TShark 4.6.6 成功解析：

| 数据组 | 文件数 | M01 解析包数范围 | 结果 |
|---|---:|---:|---|
| NetPlier NDSS 2021 | 9 | 100～114 | 全部 `status=ok` |
| Wireshark 4.6.0 | 6 | 1～98 | 全部 `status=ok` |

NetPlier 中除 `dhcp_100.pcap` 外，其余八个 `.pcap` 文件的内容结构实际为 PCAPNG。该差异被保留，可用于验证 M01 按内容而非扩展名识别格式。

BinaryInferno 的 6 个文件各含 100 条非空 Hex 消息；共 600 条均满足偶数字符的十六进制格式，没有无效行。它们不含捕获时间、方向或会话信息，因此只用于 M02～M06，不用于 M09～M11。

## 使用建议

1. M01/M07：先用 DHCP、DNS 非标准端口、DNP3、Modbus、DTN 和 OPC UA 检查内容识别及 dissector 证据。
2. M03～M06：使用 BinaryInferno 的 BGP、MAVLink、tutorial 与两组随机负例比较分帧、聚类、对齐和字段候选。
3. M08：`http-brotli.pcapng` 当前应成为“不支持 Brotli 时明确降级”的负例；不能把未恢复内容报告成明文。
4. M09/M10：优先使用具有 TCP flow 的 DNP3、Modbus、SMB/SMB2、HTTP、DTN 和 OPC UA；UDP/ICMP 抓包没有 TCP stream 并非失败。
5. M11：这些样例没有可靠的行为类别和采集分组真值，不应用协议文件名直接训练并宣称行为分类效果。

## 许可和安全边界

NetPlier 与 BinaryInferno 仓库使用 GPL-3.0；Wireshark 仓库主要使用 GPL-2.0-or-later。NetPlier 的抓包来自多个公开上游，Wireshark 的个别测试抓包也可能具有各自来源条件，因此清单保留了“上游来源仍需逐文件核对”的限制。所有样例仅作离线教育和回归测试，不用于流量回放。

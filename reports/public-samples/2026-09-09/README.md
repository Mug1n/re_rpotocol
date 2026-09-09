# 公共协议样例总体测试报告

生成日期：2026-09-09

## 总览

本次共测试 21 个固定输入。完成 0 个，带预期限制完成 20 个，带模块失败完成 1 个。

`not_applicable` 表示输入不具备模块所需元数据或真值，不计为运行失败。例如 Hex 消息集没有时间戳和方向，因此不能执行 M09；没有行为标签，因此不能执行 M11。

## 样例矩阵

| 样例 | 标称协议/类型 | 结果 | M01 | M03 | M07 | M09 | M10 | M12 |
|---|---|---|---|---|---|---|---|---|
| [netplier-dhcp-100](netplier-dhcp-100.md) | DHCP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [netplier-dnp3-100](netplier-dnp3-100.md) | DNP3 | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [netplier-icmp-100](netplier-icmp-100.md) | ICMP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [netplier-modbus-100](netplier-modbus-100.md) | Modbus/TCP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [netplier-ntp-100](netplier-ntp-100.md) | NTP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [netplier-smb-100](netplier-smb-100.md) | SMB | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [netplier-smb2-100](netplier-smb2-100.md) | SMB2 | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [netplier-tftp-100](netplier-tftp-100.md) | TFTP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [netplier-zeroaccess-100](netplier-zeroaccess-100.md) | ZeroAccess malware traffic | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [binaryinferno-bgp-100](binaryinferno-bgp-100.md) | BGP | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [binaryinferno-mavlink-100](binaryinferno-mavlink-100.md) | MAVLink | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [binaryinferno-mirai-100](binaryinferno-mirai-100.md) | Mirai malware traffic | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [binaryinferno-tutorial-100](binaryinferno-tutorial-100.md) | BinaryInferno tutorial/custom format | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [binaryinferno-random-variable-100](binaryinferno-random-variable-100.md) | Random variable-length negative control | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [binaryinferno-random-fixed-100](binaryinferno-random-fixed-100.md) | Random fixed-length negative control | `completed_with_limits` | `ok` | `complete` | `not_applicable` | `not_applicable` | `not_applicable` | `partial` |
| [wireshark-dhcp-pcapng](wireshark-dhcp-pcapng.md) | DHCP | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [wireshark-dns-nonstandard-port](wireshark-dns-nonstandard-port.md) | DNS on non-standard port | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [wireshark-http-brotli](wireshark-http-brotli.md) | HTTP with Brotli content encoding | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [wireshark-protobuf-default-value](wireshark-protobuf-default-value.md) | Protocol Buffers test protocol | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `empty` | `empty` | `partial` |
| [wireshark-dtn-bpv7-tcpclv4](wireshark-dtn-bpv7-tcpclv4.md) | Delay-Tolerant Networking BPv7 over TCPCLv4 | `completed_with_limits` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `partial` |
| [wireshark-opcua-signed](wireshark-opcua-signed.md) | OPC UA signed messages | `completed_with_failures` | `ok` | `-` | `tool_unavailable` | `ok` | `ok` | `failed` |

## 汇总结论

- 出现模块失败：M12=1。详见对应样例报告。
- 0 个抓包产生了 M07 批准协议字段证据；其余抓包的来源协议标签不能替代本地识别证据。
- BinaryInferno 消息通过派生 u32be 长度包装进入 M03～M06；该包装只用于可重复测试，不证明原协议包含同样的长度字段。
- 本批数据没有可靠的行为类别、采集任务和泄漏安全分组，因此总体报告不提供 M11 准确率。

## M07 协议证据

- 未获得批准协议字段证据。

## 安全与解释边界

- ZeroAccess 和 Mirai 仅作离线分析，禁止回放、执行载荷或连接捕获地址。
- 高熵、聚类、稳定字段和周期模式都不是加密、协议语义、应用身份或恶意性的单独证明。
- 报告中的协议名称来自冻结清单；本地识别结论必须另外有 M07 批准字段证据。

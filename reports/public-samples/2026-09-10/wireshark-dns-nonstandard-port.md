# wireshark-dns-nonstandard-port 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `wireshark-v4.6.0-captures` |
| 标称协议/类型 | DNS on non-standard port |
| 路径 | `raw/wireshark-v4.6.0/dns_port.pcap` |
| 大小 | 1318 bytes |
| SHA-256 | `78c3c00e4cb155118468e540a6151ca222fa50edd626daf1582d25e3d79626a1` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcap; packets=4, flows=0, streams=0 |
| M02 | `ok` | entropy=5.2780038216875615; printable=0.2959028831562974; zero=0.26479514415781485 |
| M07 | `ok` | observations=4; protocols=dns |
| M08 | `not_applicable` | no reassembled TCP direction was available |
| M09 | `empty` | flows=0; packets=0; unavailable=0 |
| M10 | `empty` | observations=0; patterns=none |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=6; report_status=partial |

## 主要观测

- Approved protocol evidence: dns

## 限制

- 未记录额外限制；仍不得把统计相关性当成协议语义真值。

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

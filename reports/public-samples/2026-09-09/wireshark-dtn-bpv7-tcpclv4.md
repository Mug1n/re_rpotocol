# wireshark-dtn-bpv7-tcpclv4 测试报告

生成日期：2026-09-09

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `wireshark-v4.6.0-captures` |
| 标称协议/类型 | Delay-Tolerant Networking BPv7 over TCPCLv4 |
| 路径 | `raw/wireshark-v4.6.0/dtn_tcpclv4_bpv7_transfer.pcapng` |
| 大小 | 3960 bytes |
| SHA-256 | `84bc311ead8bcaa77d63cf30f5bb9b4f7292ef3a8b8c51623e69faaae20bc664` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=29, flows=1, streams=1 |
| M02 | `ok` | entropy=4.968134426083696; printable=0.21464646464646464; zero=0.38585858585858585 |
| M07 | `tool_unavailable` | observations=0; protocols=none approved |
| M08 | `no_recoverable_content` | largest TCP direction=376 bytes; recoveries=0; skipped=0 |
| M09 | `ok` | flows=1; packets=29; unavailable=0 |
| M10 | `ok` | observations=1; patterns=bursty_transfer |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=5; report_status=partial |

## 主要观测

- Traffic patterns (not application labels): bursty_transfer

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

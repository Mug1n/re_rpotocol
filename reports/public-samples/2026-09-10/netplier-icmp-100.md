# netplier-icmp-100 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `netplier-ndss2021` |
| 标称协议/类型 | ICMP |
| 路径 | `raw/netplier-ndss2021/icmp_100.pcap` |
| 大小 | 13864 bytes |
| SHA-256 | `bb831038880d0ef6bab6138469a4f398c795731d87092f44cccc9db43768ea54` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=100, flows=16, streams=16 |
| M02 | `ok` | entropy=5.32335470098346; printable=0.2013127524523947; zero=0.33698788228505483 |
| M07 | `unknown` | observations=0; protocols=none approved |
| M08 | `not_applicable` | no reassembled TCP direction was available |
| M09 | `ok` | flows=16; packets=96; unavailable=0 |
| M10 | `ok` | observations=28; patterns=bursty_transfer, direction_dominance |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=47; report_status=partial |

## 主要观测

- Traffic patterns (not application labels): bursty_transfer, direction_dominance

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

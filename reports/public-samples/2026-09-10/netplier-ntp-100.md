# netplier-ntp-100 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `netplier-ndss2021` |
| 标称协议/类型 | NTP |
| 路径 | `raw/netplier-ndss2021/ntp_100.pcap` |
| 大小 | 13044 bytes |
| SHA-256 | `bc82a5cc53b392e402dc598251331bd071c4e96d030bb2a6e786acc2415509f9` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=100, flows=0, streams=0 |
| M02 | `ok` | entropy=5.48018259194838; printable=0.22853419196565472; zero=0.34115302054584484 |
| M07 | `unknown` | observations=0; protocols=none approved |
| M08 | `not_applicable` | no reassembled TCP direction was available |
| M09 | `empty` | flows=0; packets=0; unavailable=0 |
| M10 | `empty` | observations=0; patterns=none |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=3; report_status=partial |

## 主要观测

- 未获得超出模块状态和指标的强证据。

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

# netplier-dnp3-100 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `netplier-ndss2021` |
| 标称协议/类型 | DNP3 |
| 路径 | `raw/netplier-ndss2021/dnp3_100.pcap` |
| 大小 | 15836 bytes |
| SHA-256 | `71d28bb382463296d7b95a1a82ea8f943914935ec0159c9a8e9b9ee86ccd8bd5` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=114, flows=4, streams=4 |
| M02 | `ok` | entropy=5.290671227398412; printable=0.2481687294771407; zero=0.34996211164435465 |
| M07 | `unknown` | observations=0; protocols=none approved |
| M08 | `no_recoverable_content` | largest TCP direction=885 bytes; recoveries=0; skipped=0 |
| M09 | `ok` | flows=4; packets=114; unavailable=0 |
| M10 | `ok` | observations=4; patterns=bursty_transfer |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=11; report_status=partial |

## 主要观测

- Traffic patterns (not application labels): bursty_transfer

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

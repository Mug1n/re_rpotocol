# netplier-smb-100 测试报告

生成日期：2026-09-09

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `netplier-ndss2021` |
| 标称协议/类型 | SMB |
| 路径 | `raw/netplier-ndss2021/smb_100.pcap` |
| 大小 | 24412 bytes |
| SHA-256 | `97f914ddaebe58bd7ca98594f612e9e29d3352519ab623c926ee7b3f5206fb39` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=100, flows=5, streams=5 |
| M02 | `ok` | entropy=5.294788355672693; printable=0.2706046206783549; zero=0.40533344256922826 |
| M07 | `tool_unavailable` | observations=0; protocols=none approved |
| M08 | `no_recoverable_content` | largest TCP direction=2065 bytes; recoveries=0; skipped=0 |
| M09 | `ok` | flows=5; packets=92; unavailable=0 |
| M10 | `ok` | observations=5; patterns=bursty_transfer |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=13; report_status=partial |

## 主要观测

- Traffic patterns (not application labels): bursty_transfer

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

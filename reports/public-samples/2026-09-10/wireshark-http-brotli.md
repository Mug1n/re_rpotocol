# wireshark-http-brotli 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `wireshark-v4.6.0-captures` |
| 标称协议/类型 | HTTP with Brotli content encoding |
| 路径 | `raw/wireshark-v4.6.0/http-brotli.pcapng` |
| 大小 | 1840 bytes |
| SHA-256 | `dc3957f2348adc8f148cd776bef9e4bc2b3d062edc1b2aedc7c2a2b92b60b055` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=10, flows=1, streams=1 |
| M02 | `ok` | entropy=5.944333197921171; printable=0.4625; zero=0.23967391304347826 |
| M07 | `ok` | observations=2; protocols=http |
| M08 | `no_recoverable_content` | largest TCP direction=320 bytes; recoveries=0; skipped=0 |
| M09 | `ok` | flows=1; packets=10; unavailable=0 |
| M10 | `ok` | observations=1; patterns=bursty_transfer |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=6; report_status=partial |

## 主要观测

- Approved protocol evidence: http
- Traffic patterns (not application labels): bursty_transfer

## 限制

- 未记录额外限制；仍不得把统计相关性当成协议语义真值。

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

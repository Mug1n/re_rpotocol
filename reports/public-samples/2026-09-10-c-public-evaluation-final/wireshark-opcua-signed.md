# wireshark-opcua-signed 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `wireshark-v4.6.0-captures` |
| 标称协议/类型 | OPC UA signed messages |
| 路径 | `raw/wireshark-v4.6.0/opcua-signed.pcapng` |
| 大小 | 597228 bytes |
| SHA-256 | `a2aaa4a74040dd079de4358131864725f01634bf53477f1a23485f6a0acfc7d2` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected pcapng; packets=98, flows=3, streams=3 |
| M02 | `ok` | entropy=5.530835365041219; printable=0.9113621598451512; zero=0.010863522808709572 |
| M07 | `unknown` | observations=0; protocols=none approved |
| M08 | `no_recoverable_content` | largest TCP direction=190941 bytes; recoveries=0; skipped=0 |
| M09 | `ok` | flows=3; packets=98; unavailable=0 |
| M10 | `ok` | observations=6; patterns=bursty_transfer, direction_dominance |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=12; report_status=partial |

## 主要观测

- Traffic patterns (not application labels): bursty_transfer, direction_dominance

## 限制

- M07 found no fields from its approved protocol whitelist.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

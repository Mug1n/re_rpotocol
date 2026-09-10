# binaryinferno-mavlink-100 测试报告

生成日期：2026-09-10

## 输入

| 字段 | 值 |
|---|---|
| 数据集 | `binaryinferno-ndss2023` |
| 标称协议/类型 | MAVLink |
| 路径 | `raw/binaryinferno-ndss2023/mavlink.txt.input` |
| 大小 | 7714 bytes |
| SHA-256 | `c4caca78303589608e15a7b28308467e66dcbf23591eeaa39614b5fb188b0a98` |
| 总体结果 | `completed_with_limits` |

## 模块结果

| 模块 | 状态 | 结果摘要 |
|---|---|---|
| M01 | `ok` | detected raw_bytes; packets=0, flows=0, streams=0 |
| M02 | `ok` | entropy=6.192104402688628; printable=0.234784700505172; zero=0.27231176329083473 |
| M03 | `complete` | messages=100; unparsed_ranges=0; boundary_basis=derived u32be length |
| M04 | `ok` | clusters=10; noise=68 |
| M05 | `ok` | aligned=32; unaligned=68; mean_identity=0.8593812916191415 |
| M06 | `ok` | fields=92; boundaries=82; length_hypotheses=0 |
| M07 | `not_applicable` | no capture headers or dissector scope |
| M08 | `not_applicable` | message corpus is not an encoded-content recovery fixture |
| M09 | `not_applicable` | no packet timestamps or directions |
| M10 | `not_applicable` | no flow features |
| M11 | `not_applicable` | no behavior labels and leakage-safe collection groups |
| M12 | `partial` | evidence_records=432; report_status=partial |

## 主要观测

- Decoded 100 Hex messages; derived stream adds an explicit u32be payload length.

## 限制

- M03 boundaries come from the evaluation wrapper, not from an inferred native protocol field.

## 结论

本报告只陈述当前模块从该固定输入得到的可复现结果。协议名称来自数据源标注；只有 M07 的批准字段观测才算本地标准协议识别证据。M10 模式不是应用标签，M11 未运行时不得推断行为类别。

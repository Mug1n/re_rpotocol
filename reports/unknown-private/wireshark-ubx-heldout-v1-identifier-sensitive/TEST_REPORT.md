# 真实私有协议未见集测试报告：Wireshark UBX

日期：2026-09-11

## 测试对象与独立性

- 语料：Wireshark 公开的 `ubx_sample.pcap`，3198 个 USER1 串口抓包帧；原始 PCAP SHA-256 为 `b73ea78d54bfba92ef3075b3212a9e328392c64d3e0b7111996efd080d86b506`。
- 协议：u-blox UBX（设备厂商的二进制专有协议）。
- 留出规则：按捕获顺序每 5 条留 1 条，得到 639 条、37,878 字节的 `held_out.ubx.bin`；其余 2,559 条放入 `discovery_only.ubx.bin`，未给分析器。
- 真值：TShark 4.6.8 经 `DLT_USER 148 -> ubx` 独立解码后生成 `held_out.truth.json`，并用测试输入 SHA-256 绑定。
- 分析器输入仅为 `held_out.ubx.bin`。分析阶段不读取 UBX 协议规范、TShark 解码、真值 JSON 或发现集；评估脚本在 `run_pipeline` 返回后才加载真值。

## 结果

| 目标 | 指标 | 结果 |
| --- | --- | --- |
| 消息边界 | 精确率 / 召回率 / F1 | 1.000 / 1.000 / 1.000 |
| 消息边界 | 精确匹配消息 | 639 / 639（100%） |
| 消息类型分组 | ARI / NMI | 1.000 / 1.000 |
| 字段候选内部边界 | 精确率 / 召回率 | 0.108 / 0.513 |
| 歧义 | 可行 framing 候选数 | 3 |
| 未解析 | 未解析字节范围 | 无 |
| 聚类异常 | 噪声消息 | 1 |

M03 自动推断出“2 字节、小端、载荷长度”关系；该结论来自完整字节流的重复自洽性，不来自 UBX 定义。用于类型分组的配置仅比较每条消息最早的 4 个观测字节，不包含协议名、字段偏移或标签。

字段结果必须按“候选”理解：候选边界覆盖了 51.3% 的独立真值内部边界，但精确率为 10.8%，因此不能宣称字段语义已经恢复。此结果准确表达了模型的歧义与尚未解析的结构假设。

## 可复跑命令

```powershell
python -B scripts\prepare_wireshark_ubx_truth.py `
  --pcap data\external\wireshark-ubx-true\ubx_sample.pcap `
  --tshark "D:\新建文件夹 (2)\Wireshark\tshark.exe" `
  --output-dir data\external\wireshark-ubx-true\heldout-v1

python -B scripts\evaluate_unknown_private_protocol.py `
  --input data\external\wireshark-ubx-true\heldout-v1\held_out.ubx.bin `
  --truth data\external\wireshark-ubx-true\heldout-v1\held_out.truth.json `
  --profile profiles\unknown-private-identifier-sensitive.json `
  --output-dir reports\unknown-private\wireshark-ubx-heldout-v1-identifier-sensitive

python -B -m unittest discover -s experiments\tests -v
```

本次完整测试输出：`Ran 27 tests ... OK`。

# 候选 M1-C04：dpkt

- 类型：轻量开源 Python 包
- 核验版本：1.9.8
- 官方来源：[官方 GitHub](https://github.com/kbandla/dpkt)、[PCAP Reader 源码文档](https://dpkt.readthedocs.io/en/latest/_modules/dpkt/pcap.html)、[PyPI](https://pypi.org/project/dpkt/)
- 访问日期：2026-09-07
- 许可证：BSD
- PyPI 最新稳定版发布日期：2022-08-18

## 功能与限制

提供快速、直接的 PCAP/PCAPNG 与 TCP/IP 结构解析，但不提供满足本项目要求的通用 TCP 双向重组、重传去重与缺口表达，需要自研较多逻辑。

## 本地运行

- 单接口 PCAP 与 PCAPNG 的包数和 payload 正确。
- 在包含两个接口、不同时间精度的合并 PCAPNG 中，接口 1 的时间戳被解析为 `1788762.557...`，而 TShark 真值为 `1788762557...`，相差 1000 倍；接口 0 正常。
- 此结果表明 1.9.8 对本 fixture 的 per-interface timestamp resolution 处理不满足 M1 时间准确性要求。

证据：`experiments/M01/runs/20260907-m01-smoke/`

## 结论

不建议作为 PCAPNG 主解析器；可保留为单接口 PCAP 的轻量备选或参考。证据 E1 + E3，且关键兼容性测试失败。


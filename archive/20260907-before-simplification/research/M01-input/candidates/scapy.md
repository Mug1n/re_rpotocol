# 候选 M1-C03：Scapy

- 类型：成熟开源项目
- 核验版本：2.7.0
- 官方来源：[官方文档](https://scapy.readthedocs.io/en/latest/)、[Session API](https://scapy.readthedocs.io/en/latest/api/scapy.sessions.html)、[PyPI](https://pypi.org/project/scapy/)
- 访问日期：2026-09-07
- 许可证：GPL-2.0-only
- Python：官方元数据声明 `>=3.7,<4`

## 功能与限制

擅长数据包构造、读写 PCAP/PCAPNG 和协议层访问，非常适合生成可控 fixture。官方 `TCPSession` 依赖上层协议实现 `tcp_reassemble` 回调；不能据此推定任意未知 TCP payload 会自动得到双向、去重、缺口可追踪的完整流。

## 本地运行

成功读取 2 包 PCAP 和 6 包 PCAPNG，逐包 payload 与真值一致；并用于生成含握手、序列号缺口和重复段的重组 fixture。

证据：`experiments/M01/runs/20260907-m01-smoke/`

## 结论

建议用于 fixture 构造、补充协议解析和测试，不作为 M1 通用 TCP 重组主引擎。证据 E1 + E3；通用重组接口未验证。


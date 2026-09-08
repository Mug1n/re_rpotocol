# 候选 M1-C02：PyShark

- 类型：开源 Python 包，TShark 包装层
- 核验版本：0.6
- 官方来源：[官方 GitHub](https://github.com/KimiNewt/pyshark)、[PyPI](https://pypi.org/project/pyshark/)
- 访问日期：2026-09-07
- 许可证：MIT
- 依赖：本地 TShark；本次额外安装 lxml、termcolor、packaging、appdirs

## 功能与限制

通过 Python API 暴露 Wireshark dissector 字段，适合快速迭代和访问 `tcp.stream`、`tcp.payload` 等字段。底层能力与限制继承自 TShark，不是独立 TCP 重组引擎，也不能让裸 `.dat` 自动变成抓包。

PyPI 0.6 发布于 2023-04-26，包发布节奏明显慢于本机 Wireshark 4.6.6；集成时需固定双方版本并测试兼容性。

## 本地运行

成功读取混合 PCAPNG，枚举 6 包并返回两条 stream 的 payload，与 TShark 字段输出一致。未单独验证 Follow Stream 级重组 API。

证据：`experiments/M01/runs/20260907-m01-smoke/`

## 结论

可作为开发便利层，但生产核心路径更适合直接调用 TShark 的结构化输出以减少包装层差异。证据 E1 + E3；E2、E4 未完成。


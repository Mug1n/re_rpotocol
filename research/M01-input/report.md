# M1 数据输入与预处理

状态：已调研。整理日期：2026-09-07。

开发状态（2026-09-08）：已有内容探测、裸字节保全及 TShark 抓包提取实现。当前环境 14 项测试中 10 项通过；4 项抓包提取/重组测试因未安装 Wireshark CLI 跳过。历史 TShark 4.6.6 结果仍保留，但不等同当前复测。

用途：读取输入字节，区分原始 DAT 和抓包内容，为后续分析提供可用数据。

本报告复用旧调研已记录的来源与特点；本次未重新检索或运行候选。历史实验记录单独保留，不作为当前调研完成条件。

| 候选 | 主要特点与优势 | 输入输出及前置条件 | 限制 | 来源 |
|---|---|---|---|---|
| 标准库原始字节读取/内容识别方案 | 轻量，可作为统一输入入口；这是拟开发方案 | DAT/BIN 等文件 → 原始 bytes、格式候选与缺失元数据说明 | 扩展名不能确定格式；不能自行补出时间、方向或 TCP 会话 | [已有输入契约](../../archive/20260907-before-simplification/research/M01-input/dat-input-contract.md) |
| TShark | 协议解析、结构化字段与 Follow Stream 能力较完整 | 支持的抓包容器 → 协议字段及流内容；后续使用需要 Wireshark/TShark | 任意裸 DAT 不能直接按抓包处理；完整适配仍需开发 | [官方手册](https://www.wireshark.org/docs/man-pages/tshark.html)、[Follow Stream](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html) |
| PyShark | Python 包装层，便于访问 TShark 解析字段 | 抓包 → Python 对象；依赖 TShark | 增加包装层，能力与限制受底层 TShark 影响 | [官方仓库](https://github.com/KimiNewt/pyshark) |
| Scapy | 灵活读写与构造数据包，适合作为补充工具 | 抓包/数据包 → Python 数据包对象 | 通用未知 payload 重组不能仅凭 TCPSession 名称假定支持，需关注协议回调要求 | [Session API](https://scapy.readthedocs.io/en/latest/api/scapy.sessions.html) |
| dpkt | 轻量基础包解析库 | PCAP/PCAPNG → 包结构 | 完整 TCP 重组需要额外实现；旧记录中的混合接口时间戳问题留待开发时核验 | [官方仓库](https://github.com/kbandla/dpkt)、[旧报告](../../archive/20260907-before-simplification/research/M01-input/report.md) |

初步建议：使用原始字节读取与内容识别方案作为入口，内容确认为抓包后交给 TShark。需要 Python 字段访问便利性时考虑 PyShark，Scapy 用于补充包操作，dpkt 作为轻量备选。

待核实：真实 DAT 的内部格式及元数据可用性。此缺口影响后续适配，不阻塞 M2～M12 的资料调研。

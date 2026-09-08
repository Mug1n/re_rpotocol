# M1 数据输入与预处理：检索日志

当前状态：running  
检索日期：2026-09-07

| 日期 | 平台 | 查询词 | 有效来源 | 核验结果 | 筛选 / 排除理由 |
|---|---|---|---|---|---|
| 2026-09-07 | Web | `Wireshark User Guide tshark follow TCP stream` | [TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)、[Follow Stream](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html) | 官方文档确认 `-z follow,tcp,hex,<stream>`、双向区分及 TCP stream 支持 | 保留为主候选 |
| 2026-09-07 | Web | `PyShark official GitHub KimiNewt` | [GitHub](https://github.com/KimiNewt/pyshark)、[PyPI](https://pypi.org/project/pyshark/) | 确认其为 TShark Python 包装层；0.6、MIT、2023-04-26 发布 | 保留为便利层候选 |
| 2026-09-07 | Web | `Scapy official documentation sessions TCP reassembly` | [Session API](https://scapy.readthedocs.io/en/latest/api/scapy.sessions.html)、[PyPI](https://pypi.org/project/scapy/) | `TCPSession` 的重组依赖协议 `tcp_reassemble` 回调；2.7.0、GPL-2.0-only | 保留用于 fixture 与补充解析 |
| 2026-09-07 | Web | `dpkt official GitHub pcap Reader` | [GitHub](https://github.com/kbandla/dpkt)、[PCAP Reader](https://dpkt.readthedocs.io/en/latest/_modules/dpkt/pcap.html)、[PyPI](https://pypi.org/project/dpkt/) | 1.9.8、BSD；定位为快速基础包解析 | 保留轻量候选，需自研重组 |
| 2026-09-07 | Web | `RFC 9293 retransmission sequence number TCP` | [RFC 9293](https://www.rfc-editor.org/info/rfc9293/) | TCP 每个 octet 使用序列号；重叠段只保留新数据，是去重与重组验收依据 | 作为算法与协议标准依据 |
| 2026-09-07 | Web | `IETF pcapng Section Header Block magic` | [IETF PCAPNG 草案](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)、[Wireshark wiretap 探测说明](https://www.wireshark.org/docs/wsar_html/wtap_8h.html) | 核实 PCAPNG SHB 类型 `0x0A0D0D0A`、Byte-Order Magic 以及内容 magic 优先于扩展名 | 用于 DAT 内容分流 |
| 2026-09-07 | Web | `tcpdump pcap savefile format magic number` | - | tcpdump.org 被 robots.txt 阻止访问 | 保留失败记录，改用 Wireshark 官方格式字段与本地 capinfos 核验 |
| 2026-09-07 | Web | 首轮四查询组合 | - | 首次返回 `connection failed: error sending request`，随后重试成功 | 记录瞬时失败，不作为候选失败 |

## 停止扩展条件

首轮四个候选均已核实并本地运行；TShark 已表现出最完整的抓包重组能力。由于常规输入为 `.dat`，主路径改为 DAT 内容探测与裸字节适配器，TShark 只负责被内容证据识别为抓包的分支。除非统一适配器暴露新缺口，不再扩展 M1 候选。

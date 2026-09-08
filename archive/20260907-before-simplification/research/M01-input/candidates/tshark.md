# 候选 M1-C01：Wireshark / TShark

- 类型：成熟开源项目
- 核验版本：TShark 4.6.6，构建标识 `v4.6.6-0-g3a22c3ef473d`
- 官方来源：[TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)、[Follow Stream 用户指南](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- 访问日期：2026-09-07
- 许可证：GPL-2.0-or-later（由本机 `tshark --version` 输出核验）

## 功能与限制

支持 PCAP/PCAPNG、显示过滤器、协议字段导出、TCP stream 编号和按方向 Follow TCP Stream。TCP 分析器可标记缺失段、疑似重传等异常。

不直接接受任意裸 `.dat/.bin`；本地测试均以退出码 3 拒绝。Follow Stream 给出重组流偏移，但本次 `frame.file_off` 未产生值，因此源文件偏移需要适配层补充或返回 `null` 并说明。

## 本地运行

- PCAP/PCAPNG：6 包、2 条 TCP 流均正确枚举。
- 正常分段：stream 1 的客户端三段被重组为 `HELLO WORLD!`，服务端为 `ACK`。
- 乱序/重复 fixture：客户端重组仍精确为 `HELLO WORLD!`，重复数据未重复计入；分析字段标记了 lost segment 和 retransmission。
- 截断抓包：6 包均显示 `cap_len=50 < frame.len=60`，TCP 声明长度仍可见但 payload 不可得。
- 裸数据：`.dat/.bin` 均返回“不属于可理解的抓包格式”，退出码 3。

证据：`experiments/M01/runs/20260907-m01-smoke/`

## 结论

建议作为 PCAP/PCAPNG 主解析与 TCP 重组基线；与轻量裸字节适配器组合。当前证据 E1 + E3，尚缺统一 CLI 接口和公平对比，未达到 E4。


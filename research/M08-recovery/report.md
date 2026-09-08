# M8 明文提取与数据恢复

状态：已调研。检索日期：2026-09-07；仅资料比较，未安装或测试。

用途：从可见字节及已解析载荷中提取文本、解码或解压内容，并保留来源链。

| 候选 | 主要特点与优势 | 输入输出及前置条件 | 限制 | 来源 |
|---|---|---|---|---|
| Python 文本/Hex/Base64 工具 | bytes.decode、bytes.fromhex 和 base64 支持明确格式的可逆转换 | 字节/编码字符串及候选字符集 → 文本或 bytes；支持严格 Base64 校验和 URL-safe 变体 | 解码成功不证明有业务语义；Hex 展示不等于明文恢复，错误替换可能丢信息 | [bytes](https://docs.python.org/3/library/stdtypes.html#bytes)、[base64](https://docs.python.org/3/library/base64.html) |
| gzip / zlib | gzip 容器及 zlib/适当参数下的 raw DEFLATE 解压 | 完整或可处理的压缩流、正确封装和必要字典 → 解压字节 | 任意高熵数据不是压缩流；截断、错误校验或缺少字典可失败；需限制解压输出规模 | [gzip](https://docs.python.org/3/library/gzip.html)、[zlib](https://docs.python.org/3/library/zlib.html) |
| TShark Follow Stream / Export Objects | 利用协议重组结果提取流内容或支持协议的对象 | 抓包及适用 dissector，必要时解密材料 → 流或文件对象 | Export Objects 仅覆盖支持的协议；缺包、只抓控制通道或加密均限制恢复 | [官方手册](https://www.wireshark.org/docs/man-pages/tshark.html)、[TLS](https://wiki.wireshark.org/TLS) |

初步建议：先使用协议解析确定的载荷与编码声明，再尝试严格文本、Hex/Base64 和 gzip/zlib 转换；没有协议声明时只输出候选。文本扫描采用可配置最短长度和编码，ASCII 可打印片段不等于全文，UTF-8/UTF-16 等需分别处理。

每个恢复结果拟保留输入文件、流/消息编号、偏移范围、转换顺序、失败原因及完整性说明。编码/压缩可能多层嵌套，建议限制层数和总输出；这是后续实现要求，本阶段没有生成恢复文件。

待核实：样本编码、压缩封装及是否存在完整对象或会话密钥。Base64/Hex 是编码，不是加密；没有适用密钥不承诺恢复 TLS/AES 明文。随机密文里偶然出现可打印字符串，只能报告为片段候选。

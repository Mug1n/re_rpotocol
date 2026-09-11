# M08 受限内容恢复

对一个明确的字节来源执行严格 UTF-8/UTF-16、Hex、Base64、gzip 与 zlib 检测，保存每层转换、输出哈希、半开区间来源和安全限制。成功解码只表示候选内容，不表示协议语义；TLS/SSH 没有解密材料时使用 `--encrypted-protocol` 明确跳过。

```powershell
python experiments\M08\run.py <bytes> --output-dir <new-directory> --expected-sha256 <sha256>
python experiments\payload_sources.py <m01-result.json> --output-dir <new-payload-directory>
python experiments\M08\run.py --payload-sources <payload_sources.json> --payload-source-id <source-id> --output-dir <new-recovery-directory>
python -B -m unittest discover -s experiments\M08\tests -v
```

`payload_sources.py` 遍历 M01 的全部 TCP 流和两个方向，按 HTTP `Content-Length` 或 `Transfer-Encoding: chunked` 提取每个请求/响应正文。输出保留流、方向、消息序号、原始重组流哈希以及一个或多个半开来源区间；chunked 正文不会被伪装成单一连续范围。M08 消费该清单时重新验证清单、正文文件、重组流文件和来源区间，普通文本及 gzip/zlib/deflate 内容可形成 `protocol_declared` 恢复；不完整重组永远只能得到 `partial`，Brotli 等未支持编码明确写入 `UNSUPPORTED_CONTENT_ENCODING`。

主要预算参数为 `--max-input-bytes`、`--max-depth`、`--max-output-bytes`、`--max-inflation-ratio`、`--max-artifacts` 与 `--min-printable-length`。输入大小会在完整读取前检查；`max_depth` 是转换链长度上限（`0` 表示不执行转换）；`max_output_bytes` 是所有唯一输出字节的累计上限，相同字节经不同证据链到达时复用同一恢复文件，但保留每条转换链。gzip 会完整处理串联成员并对全部成员共同应用输出与膨胀预算；gzip 成员后的非成员数据和 zlib 尾随数据都会作为失败处理，不会把前缀误报为完整恢复。

输出目录必须不存在；源哈希不匹配、输入超过上限或输入参数非法时不会留下最终目录。运行中产生结果时先写临时目录，Schema 校验和全部文件写入成功后才原子发布。

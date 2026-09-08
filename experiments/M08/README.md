# M08 受限内容恢复

对一个明确的字节来源执行严格 UTF-8/UTF-16、Hex、Base64、gzip 与 zlib 检测，保存每层转换、输出哈希、半开区间来源和安全限制。成功解码只表示候选内容，不表示协议语义；TLS/SSH 没有解密材料时使用 `--encrypted-protocol` 明确跳过。

```powershell
python experiments\M08\run.py <bytes> --output-dir <new-directory> --expected-sha256 <sha256>
python -B -m unittest discover -s experiments\M08\tests -v
```

主要预算参数为 `--max-depth`、`--max-output-bytes`、`--max-inflation-ratio`、`--max-artifacts` 与 `--min-printable-length`。输出目录必须不存在；源哈希不匹配或输入非法时不会留下最终目录。

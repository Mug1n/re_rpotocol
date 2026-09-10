# Role B handoffs

## B-G1-local-001

- producer：B
- consumers：C（采集服务）、A（payload source 与 recovery artifact）
- task：B1；包含 B2 的普通正文/gzip 最短恢复链
- code_ref：`7625ca0`，本地分支 `codex/acceptance-b-recovery`；文件清单见 `docs/acceptance/status/b.md`
- 状态：`ready_for_consumer_local`。跨机器消费前仍需推送该提交；本记录不表示 A/C 已签收。

### 服务与固定内容

启动：

```powershell
python -B scripts\acceptance_http_server.py --host 127.0.0.1 --port 8080 --ready-file tmp\acceptance-http\ready.json --record-dir tmp\acceptance-http\uploads
```

采集操作示例：

```powershell
curl.exe --output tmp\download.bin http://127.0.0.1:8080/download
curl.exe --output tmp\chunked.bin http://127.0.0.1:8080/chunked
curl.exe --output tmp\gzip.bin http://127.0.0.1:8080/gzip
curl.exe --data-binary @tmp\upload-input.bin http://127.0.0.1:8080/upload
curl.exe http://127.0.0.1:8080/periodic
```

固定响应真值：

| endpoint | decoded length | decoded SHA-256 |
|---|---:|---|
| `/download`、`/gzip`、`/zlib` | 101 | `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07` |
| `/chunked` | 53 | `320d44725007dbd8dfb1e30fcbecbd18c6cc246da267b365aeac1a7b0233e6ee` |
| `/periodic` | 33 | `6463936324c6130e7cdfc9c8423e703eeb6b797bd8104fba530c2551d4557575` |

本机冒烟 `ready.json` 位于 `tmp/b-http-smoke/ready.json`，SHA-256 为 `b37a69db8c08e08ba449d4c053ecd87965041a69a92fdea9363d2a98bcfebfd`；该文件含随机端口，仅作本机证据，不作为跨机器固定 artifact。上传 `known-upload` 的保存文件哈希为 `4c59b9bd30ec283a1e05c4856e12ee91dd150b7c2f513b70c1807f586269e6cd`。

### Payload source 与恢复接口

```powershell
python -B experiments\payload_sources.py <m01-result.json> --output-dir <new-payload-dir>
python -B experiments\M08\run.py --payload-sources <new-payload-dir>\payload_sources.json --payload-source-id <source-id> --output-dir <new-recovery-dir>
```

- payload source Schema：`research/M08-recovery/payload-sources.schema.json`，版本 `0.1`。
- recovery Schema：`research/M08-recovery/recovery.schema.json`，版本 `0.1`；新增字段为可选，旧 M08 artifact 继续有效。
- 每个来源包含 M01/流/方向/消息 ID、HTTP framing、content encoding、流 artifact 哈希、离散范围、提取正文及哈希。
- M08 消费前重新验证整条链；完整 HTTP 正文输出 `protocol_declared`，截断正文保持 `partial`，Brotli 明确跳过。

### 消费者检查

```powershell
python -B -m unittest experiments.tests.test_payload_recovery_pipeline -v
python -B -m unittest discover -s experiments/M08/tests -v
```

预期分别为 16/16 和 12/12 通过。A 需将每个 `payload_sources`/M08 结果作为独立 artifact 实例纳入运行清单；C 需从固定服务响应之外独立保存 truth，并验证恢复输出哈希。当前未提供真实抓包 artifact，且未声称 C 已采集或验收。

### 协议/恢复设计与讲解页素材

正文链的信任边界为：M01 重组流及哈希 → 严格 HTTP 起始行与 framing 头识别 → `Content-Length` 连续范围或 chunk data 离散范围 → 正文文件及哈希 → M08 有界转换链。`recognition_basis=strict_http_start_line_and_framing_headers` 说明协议依据来自解析；它不会把随机流、文件名或调用方包装冒充协议识别。M08 消费时重新验证父 M01、流、范围重建和正文四层一致性，任一层被篡改均在写输出前失败。

建议 PPT 技术页用一张五段箭头图展示上述链路，右侧列出三条边界：不完整传输只标 `partial`；无密钥 TLS/SSH 不解密；Brotli 当前明确 `UNSUPPORTED_CONTENT_ENCODING`。现场用 `/download` 与 `/gzip` 各演示一次，展示恢复文件 SHA-256 与冻结 truth 一致；不要用测试内构造流代替 C 的正式 DAT。

原生 DAT 结构页可直接引用 `data/external/validation.md` 的已保存结论：WatchPAT 的 15 条 `[u32le length][payload]` 记录覆盖全部 8469 字节，M05 去 gap 后逐字节重建，M06 在偏移 0 恢复剩余长度关系；Audiobeat 使用有来源说明的固定 238 字节规则，并明确不产生虚假长度字段。规则来源必须与自动候选分开讲。

负例矩阵：随机非 HTTP 流不生成 payload；截断 Content-Length/chunked 或不完整 M01 不能宣称完整；输入/输出/膨胀预算超限会拒绝；父 artifact、流或正文篡改会在输出前失败；无密钥 TLS/SSH 与 Brotli 都以机器可读原因跳过。CLI 同时指定直接输入和 payload source、或遗漏 source ID 时返回 2 且不创建输出目录。

### 未完成与限制

- 实现已提交为 `7625ca0`，但尚未推送，跨机器仍不可获取。
- 当前环境无 TShark，尚未从真实抓包生成 M01 双向流。
- A 的 G0 清单契约尚未出现，字段适配待交付后核对。
- Brotli 不支持；无授权密钥的 TLS/SSH 不做解密；HTTP 无长度且非明确无正文的响应保留为未解析范围。

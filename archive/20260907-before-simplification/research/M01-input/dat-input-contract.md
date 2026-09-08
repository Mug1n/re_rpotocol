# M1 DAT 优先输入契约

状态：已确认需求，待统一 CLI 实现

## 1. 核心约束

项目的常规输入是 `.dat`。扩展名只作为用户提供的文件名信息，不作为格式结论。程序必须读取内容证据后分流：

1. 内容明确匹配 PCAP/PCAPNG 等已知抓包容器时，进入抓包解析分支。
2. 未匹配已知容器时，按连续原始字节流处理。
3. 若后续发现可靠的记录边界或自定义容器结构，只能作为带证据的候选，不能在 M1 阶段臆造。

即使文件名是 `.dat`，也可能实际承载 PCAP/PCAPNG；即使内容看起来像报文，也不能在缺少网络头时补造 IP、端口、方向或时间戳。

## 2. 格式探测顺序

| 优先级 | 内容证据 | 初步格式 | 后续处理 |
|---:|---|---|---|
| 1 | 首 4 字节为 `0a 0d 0d 0a`，且文件至少 28 字节；核验 offset 8 的 Byte-Order Magic、首块长度、4 字节对齐和尾部重复长度 | PCAPNG | 再要求 TShark/capinfos 实际返回 PCAPNG；仅退出码 0 不足 |
| 2 | 首 4 字节匹配 PCAP 常见大小端/微秒/纳秒 magic，且文件至少 24 字节；核验版本、全局头和记录长度 | PCAP | 再要求 TShark/capinfos 实际返回 PCAP；仅退出码 0 不足 |
| 3 | 其他已知容器 magic | 候选容器 | 记录命中规则；后续模块再解码，M1 不过度解释 |
| 4 | 无可靠 magic | raw_bytes | 保留完整字节和 `[0,length)` 范围 |

PCAPNG 的 Section Header Block 类型 `0x0A0D0D0A` 和 Byte-Order Magic `0x1A2B3C4D` 依据 [IETF PCAPNG 草案](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)；Wireshark 的格式探测说明也强调固定 magic 与扩展名是不同层级的证据。

## 3. RAW DAT 最低输出

```json
{
  "id": "input-001",
  "path": "sample.dat",
  "sha256": "<hex>",
  "length": 1234,
  "format": "raw_bytes",
  "format_evidence": [
    {
      "rule_id": "M01-FMT-NO-KNOWN-MAGIC",
      "observation": "no validated capture/container signature"
    }
  ],
  "metadata_availability": {
    "packet_boundaries": false,
    "network_headers": false,
    "flow_identity": false,
    "direction": false,
    "timestamps": false
  },
  "byte_ranges": [
    {
      "start": 0,
      "end": 1234,
      "artifact_ref": "artifacts/input-001.bin"
    }
  ],
  "warnings": [
    "File extension .dat does not define the internal format."
  ]
}
```

所有不可得网络字段输出 `null` 或 availability=false。原始文件保持只读，复制或派生产物记录 sha256。

机器可验证定义见 `input-artifact.schema.json`；`examples/*.expected.json` 是基于固定 fixture 的预期契约，不冒充尚未生成的 CLI 运行输出。

## 4. 后续模块衔接

- M2 直接对 `raw_bytes` 计算全局与滑窗特征。
- M3 在连续字节流上形成消息边界候选。
- M7 只处理被严格识别为抓包或具有明确封装的输入。
- M8 可检测编码、压缩和简单变换，但不能反向把可读内容解释成网络元数据。

## 5. 已执行的扩展名错配测试

| 文件 | 首 12 字节 | 探测结果 | 严格打开结果 |
|---|---|---|---|
| `m01-raw.dat` | `48454c4c4f20574f524c4421` | raw_bytes | TShark 拒绝，符合预期 |
| `m01-pcap-as-dat.dat` | `d4c3b2a10200040000000000` | pcap | capinfos 确认 PCAP，2 包 |
| `m01-pcapng-as-dat.dat` | `0a0d0d0afc0000004d3c2b1a` | pcapng | capinfos 确认 PCAPNG，4 包 |

这组结果验证了“后缀为 DAT 不等于裸字节，也不等于抓包；必须看内容证据”。

## 6. 伪 magic 与空输入反例

| 文件 | 表面现象 | 严格探测结论 | 工具行为 |
|---|---|---|---|
| `m01-empty.dat` | 0 字节 | raw_bytes / empty_input | capinfos 启发式标成 ERF 且退出码 0 |
| `m01-false-pcap.dat` | 以 PCAP magic 开头但仅 8 字节 | raw_bytes / global header truncated | capinfos 退出码 2 |
| `m01-false-pcapng.dat` | 以 SHB 类型和 BOM 开头但仅 16 字节 | raw_bytes / header truncated | capinfos 标成 MIME 且退出码 0 |
| `m01-truncated-pcapng-header.dat` | 12 字节不完整 SHB | raw_bytes / header truncated | capinfos 标成 MIME 且退出码 0 |

这证明严格分流必须检查“预期格式名称 + 结构”，不能把 magic 命中或外部工具成功退出单独当成确认。

## 7. 当前验收缺口

- 尚无用户真实 `.dat`，因此其是否为连续字节流、记录集合或自定义容器仍未知。
- 统一 CLI、magic 校验、错误状态和 artifact 输出尚未实现。
- 需要把当前一次性探测 baseline 固化为统一 CLI 与自动化测试。

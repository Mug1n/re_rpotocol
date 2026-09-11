# 未知私有协议自动结构推断测试报告

- 测试日期：2026-09-11
- 项目版本：`re_rpotocol-pc3`
- 测试目标：验证系统能否在**不读取真值标签、不预先提供协议格式**的情况下，对未知私有二进制流完成消息边界推断、消息类型候选划分、簇内对齐和字段结构候选生成。

## 1. 测试对象与方法

测试输入由 6 条连续的私有二进制消息构成。每条消息使用同一未知格式，内部包含类型字节、长度字节和变长负载；测试入口未向分析器传入这些结构说明或任何标签。

执行命令：

```powershell
python -B scripts\analyze.py `
  --input <unknown-private.bin> `
  --profile profiles\unknown-private.json `
  --output-dir <analysis-output>
```

分析配置：

- M03：枚举长度字段位置、宽度、字节序、长度语义和头部长度；只接受能从偏移 0 开始、连续覆盖完整输入、且至少包含 3 帧的候选。
- M04：按长度、字节分布和前缀距离进行无监督 DBSCAN 聚类。
- M05：以每个聚类代表消息为参考进行字节级 Needleman-Wunsch 对齐。
- M06：从对齐列产生固定/可变字段、字段边界和长度关系候选。

## 2. 实际结果

| 检查项 | 结果 | 说明 |
|---|---|---|
| 总体运行 | 通过 | `run_manifest.json` 状态为 `complete`。 |
| 自动消息边界 | 通过 | 识别 6 条完整消息，覆盖输入全部字节。 |
| 自动分帧假设 | 通过 | 推断为：长度字段偏移 1、宽度 1 字节、大端、表示 payload 长度、头部长度 2 字节。 |
| 消息类型候选 | 通过 | 无监督聚类得到 2 个 cluster；第 1/3/5 条属于 cluster-0，第 2/4/6 条属于 cluster-1。 |
| 簇内对齐 | 通过 | 两个聚类均具备 3 条样本，M05 输出可追溯字节对齐。 |
| 字段候选 | 通过 | M06 输出 2 个字段候选：cluster-0 的观察结构范围为 0–5 字节，cluster-1 为 0–4 字节。 |
| 真值/标签读取 | 未使用 | 测试没有向 M03–M06 提供格式描述、真值边界或消息类别标签。 |

## 3. 自动推断证据

M03 输出的被接受候选：

```json
{
  "length_offset": 1,
  "length_width": 1,
  "byteorder": "big",
  "length_mode": "payload",
  "header_size": 2
}
```

该候选可重复解释全部 6 条连续消息并完全覆盖输入，不存在未解析范围。每条输出消息保留源字节半开区间 `[start, end)` 及 `M03-INFERRED-LENGTH-PREFIX` 证据记录。

## 4. 回归测试

| 命令 | 结果 |
|---|---|
| `python -B -m unittest discover -s experiments/M03/tests -v` | 9/9 通过 |
| `python -B -m unittest discover -s experiments/tests -p test_unknown_private_pipeline.py -v` | 1/1 通过 |
| `python -B scripts/verify_acceptance.py reports/acceptance/2026-09-11-abc/acceptance.json` | `acceptance: PASS` |

新增回归覆盖包括：自动发现类型+长度+负载的重复帧，以及对随机/不重复字节拒绝分帧。后者确保系统不会把偶然出现的数值误说成协议结构。

## 5. 适用范围与限制

本次实现不是通用协议语义识别器。它当前自动接受的是具有足够重复证据的长度前缀格式；固定长度、分隔符格式、加密、压缩、截断、单条消息或样本不足的流量可能正确返回“证据不足/未分帧”。

`cluster-0`、`cluster-1` 是统计消息类型候选，不等同于已确认的协议命令、业务操作或恶意行为。M06 的字段候选同样是结构假设，需在更多独立真实流量中复核。

对于 `.pcap` / `.pcapng` 输入，可使用 `profiles/unknown-private-capture.json`。该配置先由 M01 重组 TCP 字节流，再选择最长的完整 TCP 单向流执行相同的保守结构推断；没有完整 TCP 流时将拒绝给出结构结论。

## 6. 结论

在本测试覆盖的未知长度前缀私有二进制流场景中，系统已完成“自动推断消息边界 → 区分消息类型候选 → 对齐 → 恢复字段结构候选”的闭环，并保留可检查的中间 JSON 产物和源字节范围。测试结果不应外推为对任意私有协议或任意网络流量均可自动还原。

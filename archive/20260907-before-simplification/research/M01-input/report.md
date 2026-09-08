# M1 数据输入与预处理：模块报告

状态：blocked

## 输入输出契约及前置条件

常规输入为 `.dat`，并兼容 `.bin/.pcap/.pcapng`。最低输出为：文件 hash、格式判断与证据、metadata availability、原始字节范围；只有内容被确认是抓包时才输出 packet/flow/stream 清单、方向、时间、payload 引用、重组状态、缺口和来源关联。详细约束见 `dat-input-contract.md`。

裸字节没有网络头、时间戳和方向时，这些字段必须为 `null`；不能把裸数据伪造成 TCP 会话。抓包的 stream offset 不等同于文件 offset。

## 检索范围与核实结果

已核实 TShark、PyShark、Scapy、dpkt 的官方文档、官方仓库或 PyPI 元数据，并用 RFC 9293 的 TCP 序列号、重复检测和重叠段处理规则作为重组验收依据。详细查询和链接见 `search-log.md`。

## 候选差异与排除理由

- 标准库裸字节适配器是 DAT 总入口：先做 hash、magic 核验、原始字节归档和缺失元数据声明。
- TShark 提供最完整的协议字段、会话编号和 Follow Stream 重组，作为被确认抓包后的分支主选。
- PyShark 便于 Python 访问字段，但增加包装层且发布版本较旧，作为便利层。
- Scapy 的构包能力最适合 fixture；通用未知 payload 重组仍需自研。
- dpkt 依赖最轻，但无完整 TCP 重组，且本地混合接口 PCAPNG 时间戳测试失败，不作主解析器。

## 实际运行的候选、环境和复现等级

环境：Windows 10.0.26200.9168、Python 3.12.14 虚拟环境、TShark 4.6.6、PyShark 0.6、Scapy 2.7.0、dpkt 1.9.8。

四个候选均已完成安装或版本核验，并运行自定义 fixture，证据为 E1+E3。官方完整测试套件 E2 未执行；统一接口和公平对比 E4 未完成。

## 测试用例、真值、指标及结果

1. PCAP：2 包、双向单连接；四候选均可逐包读取。
2. PCAPNG：6 包、2 条流、2 个接口；TShark/PyShark/Scapy 的包数和 payload 正确。
3. 正常分段：客户端三段应重组为 `HELLO WORLD!`；TShark 精确匹配。
4. 序列缺口与重复：TShark 标记异常，重组结果仍精确匹配，重复 payload 未重复计入。
5. 截断：`cap_len=50`、原始 `frame.len=60`，payload 缺失可追踪。
6. 裸 `.dat/.bin`：TShark 以退出码 3 明确拒绝，验证必须走裸字节分支。
7. dpkt 混合接口时间：其中一个接口时间戳相差 1000 倍，未通过。
8. DAT 内容分流：同为 `.dat` 后缀的 raw、PCAP、PCAPNG 三类 fixture 分别被内容 magic 判为 `raw_bytes`、`pcap`、`pcapng`；capinfos 对两个抓包容器严格打开成功。
9. 伪 magic：不完整 PCAP/PCAPNG 头均被保守降为 `raw_bytes` 并带具体失败原因。
10. 工具启发式反例：capinfos 对空文件返回 ERF、对伪 PCAPNG 返回 MIME，且退出码均为 0；因此确认条件不能只检查退出码。

结构化结果见 `experiments/M01/runs/20260907-m01-smoke/metrics.json`。

## 失败分析、修复和替代验证

- 首次 Web 请求瞬时失败，重试成功。
- 首次 pip 下载被沙箱套接字策略以 WinError 10013 拦截；使用获准外网后安装成功，不是包缺失。
- `frame.file_off` 在本次 TShark 输出中为空；适配器应记录为 `null` 并说明，或使用格式专用解析补充。
- dpkt 的混合接口时间精度问题不在本轮修复，主路径改用 TShark。
- capinfos/TShark 可能用启发式把无效 DAT 当成其他格式；适配器必须要求探测的目标格式与工具实际报告格式一致。

## 推荐方案及证据路径

推荐“DAT 内容探测与裸字节适配器作为总入口 + TShark 4.6.6 作为 PCAP/PCAPNG 分支 + Scapy fixture 工具”。PyShark 作为交互式开发备选，dpkt 不进入主路径。

证据：

- `research/M01-input/candidates/`
- `experiments/M01/runs/20260907-m01-smoke/`
- `data/ground-truth/m01-ground-truth.json`

## 与上下游的接口适配验证

已完成 `input-artifact.schema.json` 与 raw/empty/PCAP-as-DAT 三个预期契约样例；尚未完成统一 CLI 实际输出和 Packet/Flow/Stream 的细化 schema，因此未达到 E4。已有字段证明 TShark 可提供 packet、stream、方向、时间、payload 和异常分析所需的底层信息。

## 真实数据适用性与未验证内容

当前没有用户真实 `.dat/.bin/.pcap/.pcapng`。受控 fixture 只证明已覆盖的正常与边界条件；真实链路类型、抓包缺口、封装、硬件 offload 和文件容器仍未验证。

用户已确认常规输入后缀为 `.dat`，但尚未提供样本；因此必须默认进入“内容探测后按裸字节保守处理”的路径，而不是根据扩展名或主观预期调用网络解析器。

## 完成 / 阻塞状态、下一步及精确重跑命令

状态：`blocked`。当前目录经 `git rev-parse --is-inside-work-tree` 和 `git status` 复核均返回退出码 128；执行工作流要求可执行代码写入前存在可写 Git 检出，而用户尚未明确授权初始化。

解除阻塞后的下一步：

1. 初始化 Git 并创建 M1 功能分支。
2. 实现 M1 统一 CLI。
3. 输出 schema、payload artifact、缺失值和错误状态。
4. 增加自动化测试并完成 E4 接口验证。
5. 收到真实数据后补做格式识别与端到端适配。

精确命令见 `experiments/M01/runs/20260907-m01-smoke/commands.md`。

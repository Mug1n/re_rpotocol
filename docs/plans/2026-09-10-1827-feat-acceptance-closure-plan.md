---
title: PDF验收缺口与核心流程闭环 - Plan
type: feat
date: 2026-09-10
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-plan-bootstrap
execution: code
---

# PDF验收缺口与核心流程闭环 - Plan

## Goal Capsule

- 目标：交付能够现场从 DAT 输入得到协议识别、可核验还原文件、行为分析、行为类型和带引用解释的分析程序，并提供完整验收材料。
- 验收依据：`2026网络空间安全课程设计-new(1).pdf` 第 5 页技术探索性题目，第 6～7 页通用提交和现场展示要求。
- 本次工作：审查现有代码、既有运行产物与 PDF，形成整改方案；未修改生产代码、未重新运行测试，不把计划完成称为核心流程已经闭环。
- 执行原则：先跑通一组有真值的正例，再补负例和稳定性；每个能力必须有结果和验证依据，模块正常退出不足以通过验收。
- 收尾：本地交付及演示材料；本计划不要求推送、PR 或发送邮件。

---

## Product Contract

### Summary

现有 M01～M12 已形成模块原型及分支集成，但尚无充分证据证明 PDF 要求的整体验收闭环。剩余工作集中在统一入口、真实数据来源贯通、内容还原、行为分类推理、实际大模型解释及交付打包。

### Problem Frame

仓库以模块实现和 Schema 校验作为进度指标，而验收关心输入文件最终识别出了什么、还原出了什么、行为结论是否有依据。当前公共样例可运行，却普遍没有还原结果和行为类别。需要建立独立的验收门禁，避免把降级报告误当成功作品。

### Acceptance Audit

审查时点：2026-09-10。下表的测试结论来自已有报告和代码检查，不代表本次复跑。

| PDF要求 | 已有能力与证据 | 缺口及验收影响 | 顺序 |
|---|---|---|---|
| 二进制比特流特征分析 | M02 全局/窗口字节频率、熵、比例等；`experiments/M02/run.py` | 抓包评估直接计算容器文件特征，需区分文件层与载荷层；高熵不能作为加密结论 | P1 |
| 数据包识别、对齐 | M03 显式规则、M04 聚类、M05 对齐、M06 字段候选；两份外部 DAT 验证记录 | 公共抓包路径未调用 M03～M06；Hex 路径人为添加 u32be 长度，不能证明原协议边界推断 | P0 |
| 协议解析识别 | M07 有 8 类协议字段白名单 | 9 月 10 日 15 个抓包仅 2 个产生批准字段证据；其余 `unknown` 不能算已识别。白名单有限，不等于 TShark 不认识其余协议 | P0 |
| 数据包明文提取、数据还原 | M08 有 UTF、Hex/Base64、gzip/zlib、安全预算和输出哈希 | 评估器仅取最长 TCP 单向字节流；缺应用层正文切出和多来源遍历。HTTP Brotli 样例恢复数为 0，现有实现不支持 Brotli | P0 |
| 数据包统计、访问行为分析 | M09/M10 对 TCP 流可计算统计与模式 | M01 仅按 `tcp.stream` 建流，UDP 抓包虽然有包却没有流；不能将其解释为 UDP 数据没有时间信息 | P1，若选UDP作主验收则升P0 |
| 访问行为类型分析 | M11 有带分组训练/评估和模型保存 | 公开样例全部跳过 M11；没有 M09 到训练行的正式适配，没有加载已保存模型分析新输入的 CLI；现有预测仅来自训练任务的测试集 | P0 |
| 结合大模型和AI算法 | DBSCAN、RF 基线已存在；M12 有证据报告 | M12 即使传入 `model_adapter` 也仅记录禁用警告，未实际调用。模板报告不能覆盖“大模型结合”的实现内容 | P0 |
| DAT 协议解析和还原测试 | Audiobeat、WatchPAT 两个真实外部 DAT；`data/external/validation.md` | 前者是设备预设；后者验证长度关系，不等于已完成网络访问行为和内容语义还原；需要专门验收数据及真值 | P0 |
| PPT及现场作品展示 | 各模块 CLI 和 README | 没有面向单个输入的一键分析与自校验验收入口；没有完整演示脚本及稳定的离线演示包 | P0 |
| 分工、原理、概要/详细设计、测试、安装、源码、PPT、截屏录像 | 研究报告、协作说明、源码和零散测试说明 | 未发现最终 PPT、录像及完整交付目录；分支协作说明不等于实名成员分工和工作量占比 | P0交付 |

### Evidence Corrections

1. `reports/public-samples/2026-09-10/README.md`：21 个样例，0 个完全完成，21 个带限制完成，0 个模块失败；所有 M12 均为 `partial`，全部 M11 未运行。该目录在审查时是已有未跟踪文件，保留原样。
2. `reports/public-samples/2026-09-10/wireshark-http-brotli.md`：HTTP 识别成功、1 个流、10 个包，但 M08 `recoveries=0`。不能用它证明内容还原成功。
3. `scripts/evaluate_public_samples.py`：`evaluate_capture` 未接 M03～M06；`_largest_stream_direction` 仅选一个方向；`evaluate_hex_messages` 使用派生包装；M11 被固定设为不适用。
4. `experiments/M12/run.py:509` 附近：报告 `complete` 仅由模块是否全部出现决定，没有判断每项能力是否成功；全部模块均输出“不支持”也可能满足“完整输入”条件。必须另建业务验收判定。
5. 本次直接执行标准安装目录的 TShark `-v` 得到 4.6.6。根 README、进度和协作文档“当前未安装”的表述已过时；PATH 未找到不等于程序不存在。未复跑，因此不能把历史“130通过、6跳过”改写为当前全通过。
6. PDF 第 5 页未明确说老师会提供隐藏 DAT。仓库对课程数据的等待是既有假设，不能当作停止集成的依据。采用自备有真值数据完成开发验收，同时保留指定文件接入能力；是否另有指定数据需要从课程通知核实。
7. PDF 第 6 页上部另有评审表：个人成长30、项目创新30、产业价值25、团队协作15；随后第 6～7 页明确课程考核重点为功能、合理性、难度、工作量、文档与稳定性。材料应说明自主实现和成员贡献，不为表格额外开发与技术探索题无关的系统。

### Requirements

**分析与闭环**

- R1. 单个 `.dat` 可经统一 CLI 自动探测内容，生成运行清单、分析产物、恢复文件和可读报告；输入/输出哈希、参数、工具版本和耗时可追溯。
- R2. 对具备条件的载荷完成真实来源分帧、聚类、对齐和字段候选；所有字节须落入已分析或明确未分析范围。
- R3. 至少一条有真值的网络正例链必须同时产生结构化协议字段和非空恢复文件，恢复文件与预先冻结的原文 SHA-256 完全一致。
- R4. 有网络元数据的输入产生流量特征和行为模式；分类器能够对独立新采集输入给出行为类型，并记录训练、验证、测试数据及来源分组。
- R5. 大模型实际消费经过筛选的结构化证据，产出带可解析证据引用的解释；记录模型身份和调用结果，失效时保留确定性报告并明确模型能力未完成。
- R6. 验收状态按要求分别判断；工具缺失、无正文、分类未运行和模型未运行均不得被“输出目录存在”或“全部模块出现”掩盖。

**验收与交付**

- R7. 使用冻结的有真值正例、未知/随机负例、损坏输入及缺条件样例验证；合成、实际采集和外部公共样例分开报告。
- R8. 提供 PDF 第 6 页列出的完整提交材料，按第 7 页要求准备 15 分钟展示；身份和分工信息由真实成员资料填写。
- R9. 裸字节缺少时间、方向、标签时如实报告不适用；无授权密钥的密文不得宣称解密。未知边界不得通过伪造长度头获得“推断成功”。

### Scope Boundaries

首先完成 TCP/HTTP 和一个原生长度格式的可解释闭环。PDF 没有要求支持所有协议、所有压缩格式、任意密文解密或达到特定准确率；不把这些扩展变成先决条件。UDP 和额外协议作为后续覆盖补强，但必须明确现有能力边界。大模型与类型分析是本题已有要求，不作为可省略的增强项。

---

## Planning Contract

### Key Technical Decisions

- KTD1. 统一入口采用有分支的任务图，复用模块函数与契约，不机械串行 M01→M12。M07 使用抓包证据，M03～M06 使用消息来源，M09 使用真实包元数据，汇入 M12（R1、R2）。
- KTD2. 先用自控本地服务采集 HTTP 下载、上传、周期请求等已知行为，保存原文及采集任务日志；生成后冻结 DAT、真值与哈希。抓包改名 DAT 只证明内容探测，另用原生二进制长度格式验证分帧（R3、R4、R7）。
- KTD3. M08 前加入协议正文提取，先支持 HTTP Content-Length、chunked、gzip/zlib；遍历所选流的两个方向。Brotli 明确报告不支持，直至单独实现并有真值（R3）。
- KTD4. M11 分离训练评估与推理，冻结特征定义和模型版本；只加载项目生成并在可信清单中固定哈希的模型。标签来自采集任务，不能来自 M10 规则输出或 M04 聚类（R4）。
- KTD5. M12 保留确定性事实层，增加本地模型命令适配器。先对公开/自采无敏感内容证据完成一次真实调用；现成模型不可用时将 R5 明确标为阻塞并继续其他单元，不伪造调用。外部服务接入需要另行落实数据和调用授权（R5）。
- KTD6. 新增独立 `acceptance.json`，分离 `execution_status` 与逐要求的 `acceptance_status`；必要正例断言失败返回非零退出码，仍保留诊断报告（R6）。

### Core Flows

- F1 网络正例：DAT → 内容探测/包/双向流 → 协议识别与正文范围 → 消息及字段分析 → 原文恢复/哈希核对；包元数据同时进入特征、行为规则、新输入分类；全部证据进入实际模型解释和最终报告。对应 R1～R6。
- F2 原生裸流：DAT → 特征 → 显式候选规则 → 分帧/对齐/字段假设 → 可恢复内容 → 报告；无元数据的行为项标不适用。对应 R2、R7、R9。
- F3 失败降级：输入损坏、工具缺失、密文无密钥、无标签或模型失败 → 明确原因及已有事实 → 验收项失败/不适用；不能形成正例验收通过。对应 R6、R7、R9。

### Assumptions

自备可解译 DAT 可以用于开发验收；PDF 本身不能证明它必然被教师接受为唯一最终数据。若有额外课程通知，以通知复核，不修改既有事实。模型运行环境、成员资料和课程补充要求是待落实的外部输入，不能通过推测填充。

---

## Implementation Units

### U1. Freeze acceptance inputs and environment

覆盖 R1、R7、R8；无前置单元。

- 文件：新增 `data/acceptance/manifest.json`、`data/acceptance/truth/`、`scripts/capture_acceptance_samples.py`、`requirements.txt`；更新 `README.md`、`research/progress.md`、`COLLABORATION.md`。
- 采集 TCP/HTTP 正例，包括下载、上传、周期请求，每类建议至少 6 次独立采集任务，覆盖多个文件大小；标签描述实验操作，不泛化为任意应用身份。分组按采集任务隔离，不能切同一流的不同包到训练/测试。
- 冻结原文、抓包、DAT、时间、任务标签、分组、哈希及工具版本；真值仅供验证，不传给识别与恢复函数。
- 新增 `experiments/tests/test_acceptance_manifest.py`：清单文件及哈希、真值存在、训练/测试分组无交集、同一原文或近重复采集不跨组泄漏。
- 完成标准：至少一个可复核的 HTTP 内容正例和一个原生裸流正例已冻结；环境版本可以一条命令列出，文档状态与现场一致。

### U2. Add the single-input pipeline and acceptance gate

覆盖 R1、R2、R6；依赖 U1 的输入契约。

- 文件：新增 `scripts/analyze.py`、`scripts/verify_acceptance.py`、`research/acceptance.schema.json`、`experiments/tests/test_acceptance_pipeline.py`。
- 支持 `--input`、`--output-dir`、`--profile`、`--tshark`；分析命令不读真值，验证命令独立接收真值。参数方案为待实现接口，不能声称当前可运行。
- 保存每个来源实例及其结果；多个流不能靠重复字典键覆盖。扩展 M12 的多 artifact 输入或在校验后汇总记录，保留每个 artifact 的哈希与原始 ID。
- 测试：真实抓包内容改名 DAT、裸字节、不存在输入、输出已存在、模块异常、哈希篡改、所有模块都出现但核心内容为空、多个流和方向、多 artifact 汇总。
- 完成标准：一次分析得到可定位的总报告；一次独立验证能判定未闭环并返回非零，而不是一律报告带限制成功。

### U3. Connect message analysis and verified recovery

覆盖 R2、R3、R9；依赖 U2。

- 文件：修改 `experiments/M03/run.py`、`experiments/M07/run.py`、`experiments/M08/run.py` 及相关 Schema；新增 `experiments/payload_sources.py`、`experiments/tests/test_payload_recovery_pipeline.py`。
- 提取应用消息和正文范围，将 stream/packet 来源、方向、半开区间一路传到 M03～M08；复用 M04/M05/M06。对已知 HTTP 使用协议边界，对裸流保留显式规则来源；自动候选可有限枚举但必须报告歧义。
- 已经由人工/协议解析确定的分帧不能叫自动发现。不要把 HTTP 标准字段重新包装后的统计结果写成未知协议成功还原。
- 测试：跨 TCP 段正文、两个响应、双向流、Content-Length、chunked、gzip/zlib、截断正文、重传/缺口、随机负例、无密钥密文及不支持 Brotli。
- 完成标准：R3 的恢复原文 SHA-256 一致；分帧范围无重叠且所有剩余范围可解释；对齐可反向重建消息；报告可从恢复文件追溯源消息、流和抓包。

### U4. Close behavior classification on unseen inputs

覆盖 R4、R7；依赖 U1、U2。

- 文件：新增 `experiments/M11/build_rows.py`、`experiments/M11/predict.py`、`experiments/M11/tests/test_predict.py`、`experiments/tests/test_behavior_acceptance.py`；更新 M11 Schema、README 与 M12 适配。
- 从 M09 确定性构造固定版本特征；训练任务标签只在数据准备和评估阶段加入。训练、验证、最终测试按独立采集分组冻结，调参不得看最终测试标签。
- 评估输出混淆矩阵、各类 precision/recall/F1、macro-F1、多数类基线、样本数及分组；样本少则限制结论，不只报告单一准确率。
- 测试：保存并重载模型对独立 DAT 推理、特征缺列/版本不一致、模型哈希不匹配、缺依赖、无标签训练拒绝、单类训练拒绝、分组交叉拒绝。推理不要求新输入自带标签。
- 完成标准：新输入有实际类型输出并进入报告；最终测试每类有覆盖且如实报告误分。内部建议门槛为 macro-F1 超过多数类基线且各类 recall 非零；这是项目门禁，不是 PDF 指定分数。不满足时继续修正数据或特征，不能标类型分析验收成功。

### U5. Enable and verify actual model explanation

覆盖 R5、R6；依赖 U2，最终集成依赖 U3/U4。

- 文件：新增 `experiments/M12/model_adapter.py`、`experiments/M12/tests/test_model_adapter.py`；修改 M12 入口、Schema、README。
- 本地适配器以结构化证据输入、结构化 claims 输出；固定超时、输出大小和证据预算。保留模型身份、提示版本、输入摘要哈希、调用状态及响应记录。
- 引用 ID 存在仅证明可定位，不证明语义被支持；事实由程序输出，模型只解释已知结果和限制，越权结论拒收或移至明确的未验证假设。载荷文本当作数据，不能作为模型指令。
- 测试：有效引用、未知引用、格式错误、超时、证据中的指令文本、将高熵解释成已解密、将 burst 解释为恶意；失败可降级但 R5 不通过。
- 完成标准：至少一份真实模型调用记录和人工核对的证据解释；Mock 仅验证接口，不计实际模型验收。

### U6. Broaden protocol and UDP coverage

覆盖 R4、R7、R9；依赖 U2，主 TCP 闭环通过后执行。

- 文件：M01/M07/M09 入口与 Schema，新增 `experiments/tests/test_udp_flow_pipeline.py`，更新公共样例评估器。
- M01 增加 UDP 端口、载荷、方向和以端点/时间窗定义的流；保留 UDP 数据报边界。对公共样例中优先选取的协议逐项添加批准字段，不直接把抓包来源名称变成识别证据。
- 测试：DNS 请求响应、DHCP 广播、空载荷、重复数据报、双向/单向 UDP、时间窗边界；检查原 TCP 路径不回归。
- 完成标准：至少一份 UDP 公共样例具备包统计与可解释流范围；未实现的协议仍列 unknown。若选择 UDP 为 R3/R4 主例，本单元必须提前。

### U7. Produce the submission and rehearse

覆盖 R7、R8；依赖 U1～U5，包含已完成的 U6 范围。

- 文件：新增 `docs/delivery/`，包含任务分工、技术原理、概要设计、详细设计、测试分析、编译安装使用说明；新增 `docs/demo-script.md`、`scripts/package_submission.ps1`，保存最终 PPT 与截屏录像。
- 建立每项 PDF 要求到演示步骤、结果文件、真值断言和报告章节的索引。材料声明库/工具与自主实现各自贡献；成员工作量占比合计 100%，未知身份资料保持待填，打包前必须补齐。
- 打包采用项目相对引用，包含样例、真值、模型、来源许可和依赖说明，排除临时产物与凭据；从新目录解压运行，验证证据路径和哈希仍有效。
- 15 分钟建议：原理与自主工作 4 分钟，现场闭环 6 分钟，验证与边界 3 分钟，缓冲 2 分钟。预录视频作为故障后备，不能取代现场运行能力。
- 完成标准：新目录解压后完成同一验收用例，两次结果语义及恢复哈希一致；全套材料齐全，按 PDF 命名 ZIP。发送邮件由用户处理。

---

## Verification Contract

现有回归命令：逐模块执行 `python -B -m unittest discover -s experiments/Mxx/tests -v`（M01～M12），以及 `python -B -m unittest discover -s experiments/tests -v`。执行前修正会话内 Python 环境，使用明确的 TShark 路径；参考 `scripts/run-tests.ps1` 的环境处理，但该脚本默认只跑 M01，不能当作全套测试。

公共样例复测使用现有 `scripts/evaluate_public_samples.py --work-root <新目录> --report-root <新目录> --tshark <实际路径>`。历史报告保留，以新报告替代当前状态说明。

实施后的核心命令契约：

```powershell
python scripts/analyze.py --input data/acceptance/network-positive.dat --profile acceptance --output-dir tmp/acceptance-run-1 --tshark "C:\Program Files\Wireshark\tshark.exe"
python scripts/verify_acceptance.py --run-dir tmp/acceptance-run-1 --truth data/acceptance/truth/network-positive.json
```

以上两个入口及参数尚待 U2 实现。裸流、负例和分类留出样例分别建立对应配置，不能把真值混入分析输入。

| 门禁 | 通过条件 | 失败处理 |
|---|---|---|
| 来源与隔离 | 输入/真值固定哈希，分析不读取标签和预期结果 | 拒绝该轮验收 |
| 结构与识别 | 正例协议字段有证据；消息可重建，剩余字节已记录 | 不能将包装或人工规则当发现结果 |
| 还原 | 至少一个非空原文 artifact 与冻结真值逐字节一致 | 非零退出；空报告不能替代 |
| 行为与类型 | 真实元数据、独立输入推理、分组无泄漏、U4指标门禁通过 | 保留误分及不足，R4不通过 |
| 大模型 | 实际调用、身份记录、引用可解析且内容经核对 | 降级报告可用，R5不通过 |
| 负例 | 无凭据密文不宣称解密，未知/损坏/缺工具不冒充成功 | 阻止整体验收通过 |
| 可搬迁交付 | 全新解压目录可运行，报告、模型、恢复文件引用有效 | 修复路径和依赖后重验 |

---

## Definition of Done

工程闭环完成必须同时满足 R1～R7：至少一条网络正例完成 F1，一条裸流完成 F2，失败样例完成 F3；不能以所有模块都生成 JSON 代替能力闭环。U6 未做不阻塞 TCP 主例，但范围必须写清。

课程交付完成还必须满足 R8：文档、源码、PPT、录像、分工与可运行包齐全。各单元以其“完成标准”为局部退出条件，最终报告列出未覆盖条件及证据来源，清理本轮废弃实现，不删除用户既有产物。

PDF 记载 2026-09-12 验收，每组 15 分钟，当晚 20 点前提交。以此安排：9 月 10 日优先 U1/U2/U3，9 月 11 日完成 U4/U5 与 U7 并全链复验，9 月 12 日只处理演示和材料问题。时间是目标安排，不是对工作量的保证；若收紧范围，先推迟 U6、Brotli 和额外协议，不能静默删除还原、分类和大模型要求。

---

## Sources

- `2026网络空间安全课程设计-new(1).pdf` 第 5～7 页：本次已提取文字并渲染核对，包含第 6 页文字抽取遗漏的评分表。
- `experiments/M01/run.py`、`experiments/M07/run.py`、`experiments/M08/README.md`、`experiments/M11/run.py`、`experiments/M12/run.py`：能力边界及接口核对。
- `scripts/evaluate_public_samples.py`、`experiments/tests/test_remaining_pipeline.py`：现有链路及合成契约测试边界。
- `reports/public-samples/2026-09-10/README.md`、`reports/public-samples/2026-09-10/wireshark-http-brotli.md`：最新已有公共评估证据。
- `data/external/validation.md`、`README.md`、`research/progress.md`、`COLLABORATION.md`：真实 DAT 与历史测试状态。
- `docs/plans/2026-09-08-2053-feat-m07-m12-two-person-plan.md`：早期模块实现计划，仅作为历史背景；其中模板优先的阶段性目标不能替代本次 PDF 整体验收目标。

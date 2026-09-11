# 网络加密流量二进制分析

> **三人Codex验收协作入口：** 从 `origin/codex/acceptance-collaboration` 开始，先读 [START-HERE](docs/acceptance/START-HERE.md)。根目录 [AGENTS.md](AGENTS.md) 要求所有Codex任务读取共用执行契约，再按A/B/C角色实施；各自使用独立开发分支，按同一套核心流程验收标准交付。

面向课程设计技术探索题目的可解释分析原型：读取 `.dat/.bin/.pcap/.pcapng`，在不伪造缺失元数据的前提下，逐步完成字节特征、消息分帧、聚类、对齐、字段假设、标准协议解析、内容恢复、流量行为分析、分类与证据约束报告。

## 当前进度

- M01 输入与预处理：已有可运行实现，并已收紧 packet/flow/stream Schema 与跨引用契约。当前集成主机使用项目外置工具目录中的 TShark 4.6.8 完成真实抓包复测，20 项 M01 测试全部通过；第三方二进制不进入 Git。
- M02 二进制基础特征：已有标准库实现与边界测试。
- M03 消息边界识别：长度字段、分隔符和固定长度规则基线已实现并通过带真值测试。
- M04 消息聚类：依赖标准库的 DBSCAN 基线已实现，支持组合距离、噪声、真实消息代表、轮廓系数，以及可选 ARI/NMI。
- M05 消息对齐：字节级 Needleman–Wunsch 参考对齐已实现，保留每个对齐单元到原消息的偏移，显式区分 gap 与 `0x00`。
- M06 字段与格式推断：按列统计、连续区域、边界候选及严格长度关系假设已实现，所有结论保留样本和原始偏移证据。
- M07 标准协议：已实现 TShark 字段白名单、Decode As 追踪、工具缺失与裸字节降级；端口不作为协议证据。
- M08 内容恢复：已实现严格 HTTP Content-Length/chunked 正文来源映射及受限文本、Hex/Base64、gzip/zlib 恢复，保留双方向/多消息、离散范围、转换链与输出哈希；无密钥 TLS/SSH 和 Brotli 明确跳过。
- M09 流量特征与 M10 行为规则：严格校验输入 Schema、直接上游哈希、有限数值和参数范围，原子发布输出；仅在 M01 保留包边界、时间戳和方向时生成相应统计，不把流量模式解释为应用语义。
- M11 行为分类：只有显式标签、固定有限数值特征和类别完整的互斥分组满足要求时才训练；拒绝以 M04 `cluster_id` 充当行为标签，成功时保存带哈希的 `model.joblib`。
- M12 证据报告：已实现 M01～M11 的记录级适配、同模块多 artifact、稳定证据 ID 和确定性四章节 Markdown；模型解释由显式启用的有界 DeepSeek 适配器处理，保存的真实调用记录不含密钥并由独立验证器核对。
- ABC 集成：`scripts/analyze.py` 已提供 `--input/--profile/--output-dir/--tshark` 单输入任务图；正式结果 `reports/acceptance/2026-09-11-abc/acceptance.json` 已通过 C 的独立验收脚本。分析阶段不读取 truth 或标签。
- 真实课程 DAT：课程未提供；现已引入两个来源和许可明确的真实外部 DAT，并用 M01～M06 验证。它们能支撑开发，但不能代表课程隐藏验收数据。
- 公共测试包：已固定 21 个 NetPlier、BinaryInferno 和 Wireshark 小型样例，覆盖常见、工业、少见、自定义、恶意协议及随机负例；来源、许可、哈希和实测结果见 `data/external/test-samples-manifest.json`。

权威状态见 `research/progress.md`，技术路线见 `research/selection.md`，课程原始要求见根目录 PDF。

多人协作时请先阅读 [`COLLABORATION.md`](COLLABORATION.md)，其中汇总了当前分支范围、模块接口、真实数据、复测命令、限制和后续分工入口。

## 快速运行

统一入口首先推荐使用便携 profile；输出目录必须不存在：

```powershell
python -B scripts/analyze.py --input data/fixtures/m01-raw.dat --profile profiles/portable.json --output-dir tmp/portable-run
python -B scripts/analyze.py --input data/acceptance/frozen-20260910/captures/download-01.pcapng --profile profiles/acceptance.json --output-dir tmp/acceptance-run
python -B scripts/verify_acceptance.py reports/acceptance/2026-09-11-abc/acceptance.json
```

`profiles/acceptance.json` 为了离线可复核而复用并重新校验 C 冻结的 M01/M07，其他阶段重新运行。具备 Wireshark 的环境可单独现场重跑 M01，或使用不含 `reuse.m01/m07` 的 profile 并显式传入 `--tshark`。当前主机的路径是 `third_party/Wireshark/tshark.exe`，但该第三方安装目录不会上传；其他主机需自行安装。只有用户明确添加 `--invoke-model` 且进程内存在 `DEEPSEEK_API_KEY` 时才会发生外部模型调用。

M01 对输入做内容探测，并在确认抓包后尝试提取包、流与双向 TCP 字节流：

```powershell
python experiments\M01\run.py data\fixtures\m01-raw.dat --output-dir tmp\m01-raw
```

M02 计算全局与滑动窗口字节特征：

```powershell
python experiments\M02\run.py data\fixtures\m01-raw.dat --output-dir tmp\m02-raw
```

M03 按显式、可解释规则切分连续字节流；完整参数见 `experiments/M03/README.md`：

```powershell
python experiments\M03\run.py stream.dat --output-dir tmp\m03-stream --rule fixed --frame-size 16
```

M04 对 M03 消息做可解释 DBSCAN 聚类；完整参数见 `experiments/M04/README.md`：

```powershell
python experiments\M04\run.py tmp\m03-stream\framing.json --output-dir tmp\m04-stream
```

M05 以 M04 的真实代表消息为锚进行簇内字节对齐；完整参数见 `experiments/M05/README.md`：

```powershell
python experiments\M05\run.py tmp\m04-stream\clusters.json --output-dir tmp\m05-stream
```

M06 从 M05 对齐列提出统计字段区间和长度关系假设；完整参数见 `experiments/M06/README.md`：

```powershell
python experiments\M06\run.py tmp\m05-stream\alignments.json --output-dir tmp\m06-stream
```

M07 从 M01 抓包 artifact 提取批准的标准协议字段；M08 对明确的字节来源执行受限恢复；M09/M10 计算流量特征和非语义行为规则；M12 汇总经校验的证据：

```powershell
python experiments\M07\run.py tmp\m01-capture\result.json --output-dir tmp\m07-capture --tshark "C:\Program Files\Wireshark\tshark.exe"
python experiments\M08\run.py input.bin --output-dir tmp\m08-input
python experiments\M09\run.py tmp\m01-capture\result.json --output-dir tmp\m09-capture
python experiments\M10\run.py tmp\m09-capture\flow_features.json --output-dir tmp\m10-capture
python experiments\M12\run.py --input M01=tmp\m01-capture\result.json --input M07=tmp\m07-capture\protocols.json --input M09=tmp\m09-capture\flow_features.json --input M10=tmp\m10-capture\behaviors.json --output-dir tmp\m12-report
```

公共样例评估在抓包路径上同样需要 TShark；若它不在 `PATH`，必须显式传入：

```powershell
python scripts\evaluate_public_samples.py --work-root tmp\public-evaluation --report-root reports\public-samples\<date> --tshark "C:\Program Files\Wireshark\tshark.exe"
```

运行当前全部测试：

```powershell
python -m unittest discover -s experiments\M01\tests -v
python -m unittest discover -s experiments\M02\tests -v
python -m unittest discover -s experiments\M03\tests -v
python -m unittest discover -s experiments\M04\tests -v
python -m unittest discover -s experiments\M05\tests -v
python -m unittest discover -s experiments\M06\tests -v
python -m unittest discover -s experiments\M07\tests -v
python -m unittest discover -s experiments\M08\tests -v
python -m unittest discover -s experiments\M09\tests -v
python -m unittest discover -s experiments\M10\tests -v
python -m unittest discover -s experiments\M11\tests -v
python -m unittest discover -s experiments\M12\tests -v
python -m unittest discover -s experiments\tests -v
```

各模块 CLI 均拒绝覆盖已存在的输出目录。临时结果放在 `tmp/`，该目录不会进入 Git。
当前集成环境共发现 183 项测试；设置 `WIRESHARK_HOME=third_party/Wireshark` 后 183 项全部通过、0 项跳过。正式 ABC 清单另由 `scripts/verify_acceptance.py` 返回 `acceptance: PASS`。ISCX 外部评测可先用 `python -B scripts/reproduce_iscx_evaluation.py verify` 离线核验证据；提供原始抓包后再用同一脚本的 `prepare`、`train` 子命令完整复跑。

## 核心原则

- `.dat` 只是扩展名，格式判断来自内容和结构证据。
- TCP 分段边界不等于应用消息边界；Packet、Flow、Stream、Message、Field 分层建模。
- 缺少方向、时间戳、包边界或标签时显式报告缺失，不从字节偏移推造。
- 高熵不等于加密；编码、压缩、随机数据和密文必须保留多种可能。
- 所有推断保留来源、参数、偏移与限制，LLM 只能解释证据，不能替代解析证据。

## 后续里程碑

1. 若课程另发指定 DAT，复核封装、协议字段、时间戳、方向和标签条件，并保留与当前冻结自采结果分开的报告。
2. 在更多独立真实采集上补强 M09～M11；当前 18 个回环样例的指标不能外推为普适准确率。
3. 由三位真实成员确认姓名、最终贡献比例、PPT 截图与录像；仓库保留待填模板，不编造人工信息。

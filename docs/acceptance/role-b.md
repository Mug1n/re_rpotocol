# Role B: Protocol, Structure and Recovery

## Read First

先读 `docs/acceptance/codex-execution-contract.md`。
主任务：三人计划 `docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md` 中B1～B3、File Ownership、Shared Contract Before Coding及验收表。
原验收计划 `docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md` 中R2/R3/R7/R9、U1采集服务部分/U3、KTD2/KTD3及全局验证/完成标准。

## Scope

负责M01～M08及其Schema、`experiments/payload_sources.py`、`scripts/acceptance_http_server.py`、载荷恢复集成测试和本线技术材料。只写自己的status/b.md和handoffs/b.md。
不改A的统一入口/M12、C的数据truth/分类/独立验证器。M01变更必须交A/C做兼容检查。

## Execution Order

1. 检查基线及已有实现；接收A接口，提供来源样例与兼容意见。A契约未到时先做现有接口下的正文提取和服务工作。
2. 先交自控HTTP采集服务、固定原文和命令给C；实现普通Content-Length正文来源及原文恢复。
3. 接收C冻结主DAT，在真实包/双向流上验证多正文来源；交A可运行恢复产物。
4. 完成原生长度流的分帧/对齐/字段链、chunked/gzip/zlib与截断/随机/无密钥负例。
5. C核验恢复真值，B检查A模型解释是否受源证据支持；提供技术材料并按安装文档在新目录复跑。

## Required Handoffs

- 首批给C：服务启动、操作命令、原文及哈希；不能等B全部实现后才交。
- 给A：协议与载荷/恢复artifact、来源范围、Schema版本、正反例和重跑命令。
- 给C：真实恢复产物，由C独立读取冻结truth验证；不修改truth使其符合输出。
- 最终：结构与负例证据、本线测试记录、解释语义检查结果。

## Completion

B1～B3完成标准及消费者接收均有证据；恢复文件非空且由独立真值验证。来源包装不能冒充未知协议识别，Mock不能代替真实DAT结果。UDP、Brotli、额外协议不抢占主链工作。

## Launch Prompt

```text
你负责角色B。读取 docs/acceptance/role-b.md 并遵守其引用的执行契约。执行B1～B3的代码实现、测试和交接，不停留在计划。先检查当前工作树与已有状态，从未完成任务继续；只改角色拥有的文件。优先把采集服务交C，把真实正文和恢复结果交A。不得修改真值来匹配输出，不替其他角色填写验收结论。不创建额外Codex任务，不擅自推送或外传数据。依赖缺失时先完成本线独立工作并发布具体交接需求。
```

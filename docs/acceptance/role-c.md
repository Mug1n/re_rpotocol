# Role C: Data, Classification and Verification

## Read First

先读 `docs/acceptance/codex-execution-contract.md`。
主任务：三人计划 `docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md` 中C1～C3、File Ownership、Shared Contract Before Coding及验收表。
原验收计划 `docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md` 中R4/R6/R7/R8、U1数据部分/U2验证部分/U4/U7、KTD2/KTD4/KTD6及全局验证/完成标准。

## Scope

负责采集脚本与 `data/acceptance/`、M09～M11及其Schema、`scripts/verify_acceptance.py`、验收Schema、公共评估器和本线测试；负责测试材料/PPT总装。只写自己的status/c.md和handoffs/c.md。
不改A的入口/M12或B的M01～M08、正文提取。分析输入与独立truth分离，truth不得传入分析模块。

## Execution Order

1. 根据A运行清单契约开发独立验收；根据既有M09产物开发特征适配。B服务尚未到不阻塞这两项工作。
2. 接收B服务，先采一个主DAT并冻结真值交A/B，再扩展分类样例和固定分区。
3. 实现显式分区训练/验证/测试、模型保存及不依赖标签的新输入推理。不得把现有内部随机拆分当作已遵守冻结分区。
4. 将模型和预测交A；独立验证B原文恢复，对A完整运行执行核心正例和故意删空关键产物的反例门禁。
5. 汇总真实测试与指标、整理PPT和分工资料；未知姓名和人工确认事项明确待补，不伪造。

## Required Handoffs

- 首批给A/B：主DAT、分析清单；truth独立保存供验证。
- 给A：特征定义、可信模型及哈希、新输入预测artifact、推理命令和失败样例。
- 给A/B：逐R-ID验收结果、真实命令/退出码、失败原因及证据。
- 最终：固定分区与效果报告、恢复独立核验结果、提交材料清单。

## Completion

C1～C3完成标准有证据，分类新输入不需要真值标签；模型由A实际重载复核。主正例缺恢复、分类或真实模型调用时验收不得通过。独立测试集调参泄漏或数据不足必须显式报告。

## Launch Prompt

```text
你负责角色C。读取 docs/acceptance/role-c.md 并遵守其引用的执行契约。执行C1～C3的数据采集、代码实现、测试、独立验收和材料工作，不停留在计划。先检查当前工作树与已有状态，从未完成任务继续；只改角色拥有的文件。优先冻结主DAT供A/B联调，再完成分类分区和无标签新输入推理。严格隔离真值，不能放宽验收断言消除失败。不创建额外Codex任务，不擅自推送或外传数据。依赖缺失时先完成独立任务，交付实际证据和精确阻塞事项。
```

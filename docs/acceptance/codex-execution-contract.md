# Codex Execution Contract

## Purpose and Authority

这是三个独立Codex任务的执行契约。角色A/B/C不是要求当前任务生成三个子代理，也不是自动创建其他任务的授权。每位成员在自己的Codex任务中指定一个角色。

执行时先遵守用户最新指令和仓库工作规范。产品验收标准来自 `docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md` 的R1～R9及Definition of Done；角色、文件所有权、任务和交接来自 `docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md`。本文件定义Codex执行与续接方法，不降低产品要求。

三人计划的 `execution: code` 表示执行请求必须实现和验证代码；不能只改README、只补计划或只生成Mock后结束。用户仅要求修改计划时，仅修改文档。

## Startup

1. 阅读仓库适用的 `AGENTS.md`（若存在）、`agent.md`、本契约、自己角色入口。扫描三人计划标题，读取本角色工作包、File Ownership、Shared Contract Before Coding、Acceptance Cases and Signoff。
2. 阅读原验收计划的Goal Capsule、角色涉及的R/U/KTD、Verification Contract和Definition of Done。历史报告只作为历史证据；不要将过时进度当作当前运行结果。
3. 检查 `git status --short`、当前分支、`git rev-parse HEAD` 和相关代码。记录本角色工作树、基线及已有未提交变更，保留它们。未跟踪公共报告和计划不能因不在提交中而被忽略。
4. 默认使用各自独立checkout/worktree。不要自动切换或重置共享目录。若发现两个任务共享同一工作树，先遵守唯一文件所有权，不执行会影响其他任务的分支切换、checkout、reset或清理操作。
5. 自己的状态/交接文件若已存在，先读它们，核对产物、提交与测试证据后从未完成项继续；不要重新开始整个项目。

## Ownership and Collaboration

- 只修改三人计划File Ownership及角色入口列出的文件。共享契约与根文档由A修改，各角色Schema归各角色维护。需要新增相关模块内文件时可自主决定；跨角色文件先给出具体接口变更和影响，由负责人实现。
- 角色文档、计划和验收标准不应被执行代理为“方便完成”而降低。需要更改范围时指出与哪条R/U冲突及原因。
- 不假设另一个Codex任务能读本机 `tmp/`、未提交文件或绝对路径。交接必须提供可获取的代码/产物及哈希；仅写“见我的输出”不构成交付。
- 不同机器的提交通过团队已授权的仓库或文件传递渠道同步。没有远程共享授权时，提供可复现命令与可移交产物并指出待传递项，不擅自推送、发送消息或外传数据。
- A汇总集成；B/C交付小批结果并继续独立任务。跨角色评审以另一角色实际接收和运行记录为准，不能替另一角色填写“已确认”。

## Execution Loop

选择最早的可执行未完成任务 → 读取该任务及引用的接口/要求 → 实现最小完整变化 → 跑相应测试 → 生成真实交付产物 → 更新自己的状态与交接 → 继续下一个可执行任务。

接口尚未到达时可用明确标为Mock的样例实现消费者；最终必须替换为真实交付并验证。不要轮询空文件或长时间休眠等待其他角色；先完成无依赖工作。全部剩余工作都被真实依赖阻塞时，报告精确缺失产物及生产角色。

默认复用现有函数、Schema、哈希与原子发布方式。不要重写M01～M12或添加与验收无关的框架。前置环境不足时检查实际工具路径和版本，不能只凭PATH缺失认定未安装。

## Verification

现有测试命令，按自己修改的模块执行：

```powershell
python -B -m unittest discover -s experiments/M01/tests -v
# 将M01替换为本次修改的实际模块；不要直接执行带占位符的命令。
python -B -m unittest discover -s experiments/tests -v
```

首次先核对Python环境；必要时参考 `scripts/run-tests.ps1` 的会话环境处理。脚本默认仅跑M01，不能当作全套测试。新增测试文件按各角色工作包实现；A在集成发布前执行M01～M12及跨模块全部回归。

计划中的 `scripts/analyze.py`、`scripts/verify_acceptance.py` 等是待实现接口。先检查存在性与 `--help`，不存在则由所有者实现，不能声称已经运行。每次记录确切命令、工作目录、退出码、通过/失败/跳过数和日志相对路径；跳过不计通过。

核心验收沿用原计划。报告生成、JSON齐全、Mock通过不等于闭环通过；分类必须使用新输入，恢复必须核对真值，模型必须实际调用。错误路径必须验证不会冒充成功。

## State and Handoff Format

开始实际执行后创建自己的状态文件；路径中的role使用 `a`、`b` 或 `c`。

`docs/acceptance/status/<role>.md` 必须记录：

- role、更新时间、branch、base_commit、当前提交或“未提交”；
- 当前任务ID（A1/B1/C1等）及 `in_progress / ready_for_consumer / blocked / verified`；
- 已修改文件；本次测试命令、结果及证据路径；
- 未通过门禁、依赖角色和所需artifact；下一条可执行动作。

`docs/acceptance/handoffs/<role>.md` 每批交付必须记录：

- batch_id、producer、consumer、任务ID；
- code_ref（真实提交，或明确未提交的补丁/文件清单及其可获取位置）；
- 输入/输出artifact相对路径、SHA-256、Schema版本与来源；
- 重跑命令、依赖版本、预期结构和实际结果；
- 未完成项、Mock标记、消费者需执行的检查。

消费者将接收结果写入自己的状态文件，包含batch_id、所用提交、执行命令及结果，不修改生产者交接历史。A据此维护任务板。`ready_for_consumer` 只表示生产者交付，`verified` 必须已有实际验证证据。

## Blocking and Completion

可自行处理：模块内实现细节、测试失败、可追溯小样例、兼容适配和本角色文档。

必须明确提出：真实凭据/外发授权不足、额外课程要求改变范围、关键数据缺失、必须更改他人接口但尚未交付。只阻塞依赖它的工作，继续其他已授权任务。不以日期到点、预算紧张或接口Mock完成为理由宣告成功。

角色完成时列出本角色已通过的任务和门禁、交接批次及未完成的全局条件。只有A汇总B/C已接收证据并实际通过整体验收后，才能宣布工程闭环；最终课程交付还需实名资料、PPT、录像和可运行包。不能伪造人工复核、会议、姓名、贡献、截图或测试结果。

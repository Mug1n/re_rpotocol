# Codex acceptance collaboration

本仓库的验收协作要求适用于所有Codex任务。共享起点为远程分支 `origin/codex/acceptance-collaboration`；该分支包含执行契约、角色入口和验收计划。不要仅依据旧README进度或个人聊天历史开始实现。

## Required reading

1. 阅读 `agent.md` 的工程原则与边界；历史进度必须用当前代码和实际运行核对。
2. 阅读 `docs/acceptance/codex-execution-contract.md`。
3. 根据用户指定的角色读取 `docs/acceptance/role-a.md`、`role-b.md` 或 `role-c.md`，再按入口加载计划中的相关章节。
4. 开工前说明本任务角色、当前分支/基线、可改文件和首个交付目标。角色未指定时先检查和说明现状，向用户确认角色后再进行角色专属实现。

## Shared requirements

- A负责入口、集成、M12与实际模型调用；B负责M01～M08、协议/结构/恢复；C负责数据、M09～M11、分类和独立验收。具体文件所有权以三人计划为准，不越界修改其他角色文件。
- 三个角色都必须遵守同一产品验收契约：`docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md`。协作顺序见 `docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md`。
- 各角色从共享起点创建自己的开发分支或隔离工作树，先确认起点含上述文件。不要直接在入口分支上开展三路并发实现，不自动覆盖已有开发分支或未提交改动。
- 每个角色维护自己的 `docs/acceptance/status/<role>.md` 和 `docs/acceptance/handoffs/<role>.md`；A汇总集成。跨机器交接必须有可获取代码、产物哈希、重跑命令和消费者验证，不能只给本机临时路径。
- 用户要求执行角色工作时，实现、测试并交付可复跑结果；用户仅要求计划或审查时，不自动开始开发。不要因本文件创建子代理或额外Codex任务。
- 不以Mock、模块JSON齐全或报告生成代替核心流程闭环。协议识别、真值一致恢复、新输入分类、实际模型解释和独立验收须保留真实证据。
- 缺依赖时继续可独立工作，并明确记录阻塞；禁止伪造模型调用、标签、测试、人工确认或其他角色签收。

## Getting started

给本Codex任务发送“你负责角色A/B/C，按对应角色入口执行”即可指定角色；完整启动提示词见各角色入口。人类成员的启动与同步命令见 `docs/acceptance/START-HERE.md`。

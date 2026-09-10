# Start Here: Three Codex Tasks

## Shared Base

仓库：`https://github.com/Mug1n/re_rpotocol.git`。
共同入口分支：`codex/acceptance-collaboration`，基于已有实现提交 `2219860` 创建。

本分支供三位成员检出相同的验收要求。角色开发在各自分支进行；根目录 `AGENTS.md` 是Codex自动发现入口，三位成员仍须在任务中分别指定A、B、C，不能让三个任务都自行认领A。

首次开始时，在各自干净checkout中执行：

```powershell
git fetch origin
git switch -c codex/acceptance-a-integration origin/codex/acceptance-collaboration
```

上例是A。B使用 `codex/acceptance-b-recovery`，C使用 `codex/acceptance-c-behavior`。若目标分支已存在，检查它的基线与工作状态后继续，不使用 `-C`、reset或强制覆盖。已有未提交工作先保留；不要把切换分支当作清理改动的方法。

在Codex界面创建任务时也可以选择相同起始分支和独立工作树。若起始选项默认指向main，需要显式改为本协作入口；否则新的执行文档可能不可见。

## Prompts

分别把下面一句发给三个Codex任务；无需粘贴整个计划。

### A

```text
你负责角色A。先读取根目录AGENTS.md和docs/acceptance/role-a.md，按共用执行契约实施A1～A3。先确认当前基线包含协作入口、文件所有权和已有进度，再实现、测试、交接和集成；不要只写计划。以真实验收证据推进，不替B/C宣布完成。
```

### B

```text
你负责角色B。先读取根目录AGENTS.md和docs/acceptance/role-b.md，按共用执行契约实施B1～B3。先确认当前基线包含协作入口、文件所有权和已有进度，优先向C交采集服务、向A交真实正文及恢复结果；完成本线测试和交接，不要只写计划。
```

### C

```text
你负责角色C。先读取根目录AGENTS.md和docs/acceptance/role-c.md，按共用执行契约实施C1～C3。先确认当前基线包含协作入口、文件所有权和已有进度，优先冻结主DAT供联调，再实现独立分组分类、新输入推理和独立验收。真值与分析输入隔离，不放宽断言消除失败。
```

## Check Before Implementation

三个任务均须能读到 `AGENTS.md`、共用执行契约、角色入口及两份验收计划。先输出角色、基线、负责范围、首个交付，发现分支不含文件时先同步入口，不自行重新生成另一套要求。

本仓库的文档只保证规则可被检出和发现，不保证另一个任务已经启动或完成阅读。由各任务开工说明和真实交接记录证明执行情况；不能在尚未启动时填写三方已确认。

## Integration and Evidence

A从相同入口创建或维护 `codex/acceptance-integration` 作为集成分支；具体合并以已交付批次和消费者测试为准。成员发布自己的工作须按用户授权进行，入口分支的一次推送不代替其他任务未来操作所需的上下文授权。

9月10日公共样例报告随本入口提交，作为缺口审查引用的历史证据；不是本次重新运行产生的结果。各机器重新验证应生成新目录和记录实际工具版本，不覆盖历史报告。

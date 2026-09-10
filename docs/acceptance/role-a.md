# Role A: Integration, Report and Model

## Read First

先读 `docs/acceptance/codex-execution-contract.md`。
主任务：三人计划 `docs/plans/2026-09-10-1835-docs-three-person-acceptance-plan.md` 中A1～A3、File Ownership、Shared Contract Before Coding及验收表。
原验收计划 `docs/plans/2026-09-10-1827-feat-acceptance-closure-plan.md` 中R1/R5/R6/R8、U2/U5/U7、KTD1/KTD5/KTD6及全局验证/完成标准。

## Scope

你是唯一集成负责人。负责 `scripts/analyze.py`、M12代码与Schema、统一运行清单/profile、接口契约、依赖与打包脚本、根文档；只写自己的status/a.md和handoffs/a.md，并维护总任务板。
不修改B的M01～M08或C的M09～M11、数据真值及验收判定脚本。报告需要的新字段交给相应负责人。

## Execution Order

1. 核对基线和工具；建立G0接口契约与正反样例，发布给B/C。优先确定本地模型能否实际运行，记录身份和路径；缺模型明确阻塞，不静默替换为模板完成。
2. 实现单输入入口、版本化多artifact清单和失败状态；用现有模块连接最小路径并跑本线测试。
3. 实现真实模型适配、证据引用与报告；现有公开证据可先用于真实调用验证。
4. 接收B正文/恢复清单及C分类输出；对同一DAT运行整条链，交C的独立验证器检查。
5. 接收交叉验证证据，跑全模块回归与新目录运行，制作安装包及本线材料。

## Required Handoffs

- G0：接口版本、最小样例和多实例清单给B/C。
- G1：可运行入口与运行清单给C，保留尚未接通状态。
- G3：同一输入的完整运行产物给C验收、给B检查解释语义。
- G4：固定版本、依赖和可搬迁包，附实际回归结果。

## Completion

A1～A3的完成标准全部有证据；B/C交付已接收；本线完成不替代全局验收。尚有模型或数据阻塞时写清R-ID，不宣布全链完成。后续依赖未到先完成可独立任务。

## Launch Prompt

```text
你负责角色A。读取 docs/acceptance/role-a.md 并遵守其引用的执行契约。执行A1～A3的代码实现、测试、交接和集成，不停留在计划。先检查当前工作树与已有状态，从未完成任务继续；只改角色拥有的文件。使用实际运行证据记录进度，不替B/C宣告完成。不创建额外Codex任务，不擅自推送或调用付费/外发服务。完成本线并推进所有已具备依赖的集成；真实阻塞时准确报告缺失产物及责任角色。
```

# Role A status

- 更新时间：2026-09-11（Asia/Shanghai）
- role：A（统一入口、M12、模型与集成）
- branch：`codex/acceptance-integration`
- shared base：`a935fbdba601ce163f7c4d44c806c09efdc71246`
- implementation code_ref：`91e52dcf3e213b1a0f1fd8c6296de50383a7b40e`
- A1：`verified_local`；A2：`verified_by_independent_gate`；A3：`ready_for_human_signoff`

## 已完成

- 合并 C 线与 B 的 `7625ca0`/`b7a1412`，保留原分支；撤销 C 的 `4213cad` 纯删除提交，因为它删除了验收清单仍引用的 42 个 artifact。
- 修复冻结 Windows JSON 的检出换行策略，恢复已发布 SHA-256；C 的既有完整清单重新通过独立验证。
- 将 `scripts/analyze.py` 改为 `--input/--profile/--output-dir/--tshark` 单输入任务图。分析输入不含 truth/标签；失败删除半成品并写相邻 failure JSON。
- 新增 profile/run-manifest Schema 与 portable/acceptance profiles。artifact 使用数组记录 module、instance、scope、长度、哈希和状态。
- M12 支持同模块多 artifact；DeepSeek 适配器限制证据/请求/响应/claim，拒绝未知引用、提示注入影响和无依据安全结论，API key 不落盘。
- 新增 acceptance assembler、依赖文件、可搬迁打包脚本、接口/设计/安装/测试/演示/PPT/贡献模板。

## 正式结果

- run：`reports/acceptance/2026-09-11-abc/run/run_manifest.json`，SHA-256 `715d5b7e9e7d5d8ef379f2ba1306b317bb7795ef1c285d3ced583918559ef833`。
- acceptance：`reports/acceptance/2026-09-11-abc/acceptance.json`，SHA-256 `95bf5b6c0ff7d8f418079ca75a56905f5453d2d5b62a64ef064e2c56f0fd9946`。
- recovery：101 字节，SHA-256 `215ff970eee6a68f5e5a27bef8bea4026824a1e45d2c6024e79812617dee7c07`，与 C 独立 truth 一致。
- label-free prediction：同一 `download-01` flow 预测为 `download`，score 0.99；分数仅为该模型类概率，不作普适置信度声明。
- 2026-09-11 复现修订：本记录在本主机原样重跑，M11 阶段改用 M11 原生 v0.2 分类器，并修掉 profile 复用路径记录中的绝对路径；run/acceptance 哈希因此更新，recovery 字节不变。
- semantic model：复用并验证已授权的真实 `deepseek-v4-flash` 调用记录；未重新调用付费 API。
- C gate：`python -B scripts/verify_acceptance.py reports/acceptance/2026-09-11-abc/acceptance.json` 返回 `acceptance: PASS`，退出码 0。

## 测试与环境

- Python 3.13.9；当前主机在 Git 忽略的 `third_party/Wireshark/` 中安装 Wireshark/TShark/Capinfos 4.6.8。
- 设置 `WIRESHARK_HOME=third_party/Wireshark` 后，M01～M12 加 `experiments/tests` 顺序回归共 168 项全部通过，0 项跳过；M01 的 20 项真实工具与契约测试全部执行。
- 新增 A pipeline 5/5、M12（含模型负例）23/23、B payload 16/16 均通过。
- 干净提交打包并在新解压目录复跑：独立 gate PASS，统一 acceptance profile 成功，恢复哈希保持 `215ff...c07`；包内提交 `91e52dc`，495 个跟踪文件。

## 尚需人类/外部完成

- 当前主机已从冻结的真实 `download-01.pcapng` 新鲜重跑 M01/TShark 并通过全部 M01 测试；`profiles/acceptance.json` 仍保留冻结 M01/M07 复用，以保证无工具主机也能离线复核。
- 当前安装不含 Npcap，因此能够分析已有抓包，但不能把本机验证称为实时网卡采集。
- 三位真实成员需确认姓名、实际贡献比例（合计 100%）、最终 PPT 截图和录像。模板没有虚构这些信息。
- 若课程另发指定 DAT，需在独立报告中复跑，不能用当前自采主例代替。

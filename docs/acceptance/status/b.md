# Role B status

- 更新时间：2026-09-10（Asia/Shanghai）
- role：B（协议、结构与还原）
- branch：`codex/acceptance-b-recovery`
- base_commit：`a935fbdba601ce163f7c4d44c806c09efdc71246`
- 实现提交：`7625ca0`（本地分支，尚未推送）
- 当前任务：B1～B3 均为 `ready_for_consumer_local`；仍等待 A/C 的跨角色消费、真实采集与独立真值验收

## 已完成到本工作树

- 新增仅回环监听的确定性 HTTP 服务，提供下载、上传、周期、chunked、gzip 和 zlib 端点。
- 新增 M01 全 TCP 流、双方向、多 HTTP 消息正文提取，保留原始流 artifact、哈希及一个或多个 `[start,end)`。
- M08 可按 payload source ID 消费正文，并重新验证 payload 清单、M01 artifact、流 artifact、范围重建和正文哈希。
- 普通正文、chunked 后正文和 gzip/zlib 可保留 `protocol_declared` 依据；不完整流的恢复只能标为 `partial`；Brotli 明确标为 `UNSUPPORTED_CONTENT_ENCODING`。

## 修改文件

- `scripts/acceptance_http_server.py`
- `experiments/payload_sources.py`
- `experiments/tests/test_payload_recovery_pipeline.py`
- `experiments/M08/run.py`
- `experiments/M08/README.md`
- `research/M08-recovery/payload-sources.schema.json`
- `research/M08-recovery/recovery.schema.json`
- `docs/acceptance/status/b.md`
- `docs/acceptance/handoffs/b.md`

## 验证

- 基线：M01～M08 与 `experiments/tests` 共发现 97 项，91 通过、6 项因当前环境未检测到 TShark 而跳过。
- `python -B -m unittest discover -s experiments/M08/tests -v`：12/12 通过。
- `python -B -m unittest experiments.tests.test_payload_recovery_pipeline -v`：16/16 通过。
- B 角色全量（M01～M08 与 `experiments/tests`）：113 项，107 通过、6 项因无 TShark 跳过。
- `python -B -m unittest experiments.tests.test_real_dat_pipeline -v`：10/10 通过；WatchPAT 15 条原生长度记录完整覆盖，M05 可逐字节反向重建，M06 恢复偏移 0 的 `u32le` 剩余长度关系；Audiobeat 不虚构长度关系。
- `python -B -m unittest discover -s experiments/M12/tests -v`：17/17 通过（验证 M08 Schema 向后兼容）。
- 服务进程冒烟：真实启动随机本地端口，GET `/download`、GET `/chunked`、POST `/upload` 均成功；上传 12 字节，SHA-256 为 `4c59b9bd30ec283a1e05c4856e12ee91dd150b7c2f513b70c1807f586269e6cd`。

## 门禁、依赖与下一步

- 当前机器为 Python 3.13.9；`C:\Program Files\Wireshark\tshark.exe` 不存在，真实抓包提取仍未在本机复跑，6 项工具测试不计通过。
- A 的 `docs/interfaces/acceptance-pipeline-contract.md` 尚未到达；现接口按既有 M01/M08 契约实现，待 G0 后做消费者兼容检查。
- C 尚未冻结主 DAT/truth；当前测试使用可追溯合成 M01/HTTP 流，不宣称 AC01 已通过。
- 本线独立实现、负例、CLI 错误路径与原生长度流复核已完成；下一步将提交推送为 A/C 可获取的远端分支，接收 C 的真实采集与冻结 truth，按 G0 契约做适配，再由 C 独立核验恢复哈希。

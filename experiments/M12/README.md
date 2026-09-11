# M12 确定性证据报告与受限模型解释

校验并哈希模块 artifact，将各模块记录规范化为稳定证据 ID，生成 `evidence.json`、四章节 `report.md` 和 `report_manifest.json`。M12 本体保持确定性；`deepseek_adapter.py` 是单独、显式启用的受限解释层，由统一入口的 `--invoke-model` 调用。它限制证据、请求、响应和 claim 大小，把载荷文字视为不可信数据，拒绝未知引用以及无依据的恶意/已解密结论，并且不落盘 API key。模型失败不改变确定性事实，但不能通过模型验收门禁。

```powershell
python experiments\M12\run.py --input M01=<result.json> --input M02=<features.json> --input M07=<protocols.json> --input M08=<recovery.json> --output-dir <new-directory>
python -B -m unittest discover -s experiments\M12\tests -v
```

当前已实现 M01～M11 的记录级适配器，包括 M03 消息/未解析范围、M04 簇/噪声、M05 对齐/未对齐消息以及 M06 字段、边界和长度关系候选。未提供的模块仍会明确列入 `missing_modules` 对应的报告内容。M01～M11 各自声明的直接上游路径和 SHA-256 都会按模块契约重新解析和校验；M07 还会重新校验所引用的 M01 Schema、内部引用及 packet/flow/stream/input 作用域。单个输入默认不得超过 16 MiB（可用 `--max-input-bytes` 调整），证据在规范化过程中即受 `--max-evidence` 限制并记录确定性省略数。输出目录必须不存在。

同一模块可以重复传入多个不同 artifact，例如多个 HTTP 正文各自形成的 M08 结果：`--input M08=<first.json> --input M08=<second.json>`。报告清单逐项保留路径和哈希，不再用单一模块键覆盖后续实例；同一路径的重复项会被拒绝。

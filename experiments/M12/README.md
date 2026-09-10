# M12 确定性证据报告

校验并哈希模块 artifact，将各模块记录规范化为稳定证据 ID，生成 `evidence.json`、四章节 `report.md` 和 `report_manifest.json`。本版本只生成确定性报告：即使调用方传入模型适配器，也不会执行或呈现模型文本，并会记录固定警告。恢复模型解释前必须先提供有界的语义支持校验器。

```powershell
python experiments\M12\run.py --input M01=<result.json> --input M02=<features.json> --input M07=<protocols.json> --input M08=<recovery.json> --output-dir <new-directory>
python -B -m unittest discover -s experiments\M12\tests -v
```

当前已实现 M01～M11 的记录级适配器，包括 M03 消息/未解析范围、M04 簇/噪声、M05 对齐/未对齐消息以及 M06 字段、边界和长度关系候选。未提供的模块仍会明确列入 `missing_modules` 对应的报告内容。M01～M11 各自声明的直接上游路径和 SHA-256 都会按模块契约重新解析和校验；M07 还会重新校验所引用的 M01 Schema、内部引用及 packet/flow/stream/input 作用域。单个输入默认不得超过 16 MiB（可用 `--max-input-bytes` 调整），证据在规范化过程中即受 `--max-evidence` 限制并记录确定性省略数。输出目录必须不存在。

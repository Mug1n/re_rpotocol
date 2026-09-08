# M12 确定性证据报告

校验并哈希模块 artifact，将各模块记录规范化为稳定证据 ID，生成 `evidence.json`、四章节 `report.md` 和 `report_manifest.json`。没有模型时完全可运行；可选模型适配器失败、超时、畸形或引用不存在的证据时会被跳过，不阻断确定性报告。

```powershell
python experiments\M12\run.py --input M01=<result.json> --input M07=<protocols.json> --input M08=<recovery.json> --output-dir <new-directory>
python -B -m unittest discover -s experiments\M12\tests -v
```

当前已实现 M01、M07、M08 的细粒度适配器，以及其他已安装 Schema 模块的保守状态适配器。M09～M11 的完整记录适配器将在开发者 B 的契约落地后接入。所有输入的直接上游引用都会再次校验 SHA-256；输出目录必须不存在。

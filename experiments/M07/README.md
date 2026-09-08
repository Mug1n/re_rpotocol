# M07 标准协议识别

从经过校验的 M01 抓包 artifact 调用 TShark，仅规范化批准字段并生成 `protocols.json`。裸字节、工具缺失和未知协议均生成显式降级状态；源哈希不一致、Schema 错误或工具输出畸形则在创建最终输出目录前失败。

```powershell
python experiments\M07\run.py <m01-result.json> --output-dir <new-directory> --tshark "C:\Program Files\Wireshark\tshark.exe"
python -B -m unittest discover -s experiments\M07\tests -v
```

可重复使用 `--decode-as tcp.port==8443,http` 和可选 `--display-filter`。Decode As 会明确写入参数与识别模式；端口不会作为字段证据。TLS/SSH 握手或协商字段只表示元数据可见，不表示应用明文已恢复。输出目录必须不存在。

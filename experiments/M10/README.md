# M10 访问行为分析

M10 只读取 M09 `flow_features.json`，以固定阈值输出可复算、非互斥的统计模式：周期候选、方向主导、突发和长连接间歇。它不会把模式命名为应用、攻击或意图。

```powershell
python experiments/M10/run.py path/to/flow_features.json --output-dir runs/m10
```

时间证据缺失时，依赖时间的规则写入 `insufficient_scopes`；输出状态为 `insufficient_evidence` 或 `partial`，不伪造特征。


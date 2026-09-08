# M11 有条件行为分类

只有提供固定维特征、一个明确标签维度和互斥的 `group_id` 时，M11 才会训练可选的 Random Forest 基线；否则输出 `insufficient_labels`，不会产生准确率。

输入 JSON 采用：`{"schema_version":"0.1","feature_definition_version":"0.1","rows":[{"id":"…","group_id":"…","labels":{"application":"…"},"features":{"byte_count":12.0}}]}`。一次只选择一个标签维度，不能混用 `application` 与 `vpn_status`，也不能用聚类 ID 作为标签。

```powershell
python experiments/M11/run.py rows.json --task application --output-dir runs/m11
```

缺少 scikit-learn 时返回 `dependency_unavailable`，不伪装训练或评估已经完成。


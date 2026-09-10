# M11 有条件行为分类

只有提供固定维、有限数值特征、一个明确标签维度和互斥的 `group_id` 时，M11 才会训练可选的 Random Forest 基线；训练/测试分组还必须各自包含全部类别，否则输出 `insufficient_labels`，不会产生准确率。

输入 JSON 采用：`{"schema_version":"0.1","feature_definition_version":"0.1","rows":[{"id":"…","group_id":"…","labels":{"application":"…"},"features":{"byte_count":12.0}}]}`。一次只选择一个标签维度，不能混用 `application` 与 `vpn_status`，也不能用聚类 ID 作为标签。

```powershell
python experiments/M11/run.py rows.json --task application --output-dir runs/m11
```

输入拒绝重复 ID、特征列漂移、NaN/Inf/布尔值和 `cluster_id` 标签。训练成功后输出目录同时包含 `classification.json` 与 `model.joblib`，JSON 记录模型长度和 SHA-256；两者经严格 Schema 校验后原子发布。缺少 scikit-learn/joblib 时返回 `dependency_unavailable`，不伪装训练或评估已经完成。

验收分类准备先执行 `build_rows.py`，它只从 M09 构造固定特征行，绝不读取标签或真值。冻结分区和标签只能在独立训练准备步骤加入。`predict.py` 用 `classification.json` 中的模型哈希与特征版本验证模型后，对不含标签的新输入行推理：

```powershell
python experiments/M11/build_rows.py flow_features.json --output rows.json
python experiments/M11/predict.py run/classification.json unseen-rows.json --output prediction.json
```

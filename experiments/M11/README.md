# M11 有条件行为分类

M11 在证据边界内训练可选的 Random Forest 基线：只有输入含固定维、有限数值特征、一个明确标签维度和互斥的 `group_id` 时才训练，且至少两个类别、至少两个分组；否则输出 `insufficient_labels` / `empty`，不产生伪指标。

## 特征初始化

`features.py` 定义固定有序特征集 `FEATURE_NAMES`（当前 `FEATURE_SET_VERSION = "0.2"`，共 17 个非冗余特征），从单条 M09 flow 记录派生比例与归一化统计，避免共线派生量（如 rate、burst_max_packets）。缺任一上游字段即整行跳过并在 `warnings` 中记录原因，不补造数值。

`build_rows.py` 从 M09 的 `flow_features.json` 构造固定特征行，标签与 split 赋值有意缺席：

```powershell
python experiments/M11/build_rows.py flow_features.json --output rows.json
```

`prepare_rows.py` 是隔离的训练准备步骤：把外部提供的标签、`group_id` 与可选 `split` 注入无标签行，拒绝重复/幽灵 id、缺失 group_id 或非法 split：

```powershell
python experiments/M11/prepare_rows.py rows.json labels.json --output prepared.json
```

`labels.json` 形如 `{"schema_version":"0.1","assignments":[{"id":"flow-0","labels":{"application":"upload"},"group_id":"capture-1","split":"train"}]}`。

## 训练与评估

`run.py` 统一两种泄漏安全评估：

- 行含显式 `split`（train/validation/test）→ `explicit_partition`，train 与 test 各含全部类别时评估 test（可选 validation）。
- 行不含 `split` → `grouped_cv`，`GroupKFold` 分组交叉验证，聚合 out-of-fold 预测并报告 `cv_macro_f1_mean` / `cv_macro_f1_std` / `cv_fold_scores`。

两者都保证分组不跨越训练与评估。模型使用 `class_weight="balanced"` 缓解类别不均衡。置信度低于 `reject_threshold`（默认 0.5）的预测被标为 `rejected` 并输出 `unknown`，而非强行归入某一类：

```powershell
python experiments/M11/run.py rows.json --task application --output-dir runs/m11 \
  --reject-threshold 0.5 --cv-folds 5
```

输入拒绝重复 ID、特征列漂移、NaN/Inf/布尔值和 `cluster_id` 标签。成功训练后输出目录同时包含 `classification.json` 与 `model.joblib`，经严格 Schema 校验后原子发布；缺少 scikit-learn/joblib 时返回 `dependency_unavailable`。

`predict.py` 用 `classification.json` 中的模型哈希、特征版本与 `reject_threshold` 验证后，对不含标签的新输入行推理：

```powershell
python experiments/M11/predict.py run/classification.json unseen-rows.json --output prediction.json
```

`evaluate.py` 是闭环评估步骤：用冻结模型对**带标签的留出集**打分，不重新训练。它报告 `macro_f1`、`per_class`、`confusion_matrix`、拒识率，并把留出标签中不在模型类别里的样本当作开集计数（其唯一正确结果是拒识）：

```powershell
python experiments/M11/evaluate.py run/classification.json held-out-labeled-rows.json --task application --output eval.json
```

完整闭环：`build_rows`（特征）→ `prepare_rows`（训练集标签/分组）→ `run`（训练）→ `evaluate`（留出集打分，验分类）→ `predict`（无标签推理）→ 类外样本验拒识。

## 外部真实流量评测

在 ISCX VPN-nonVPN 2016 的真实 OpenVPN 抓包上，用 2 折会话不交叠切分评 `task=application`，得到 macro-F1 0.4995（多数类基线 0.3040），证据见 [data/external/iscx-vpn-2016/](../../data/external/iscx-vpn-2016/)，协议、结果与限制见 [docs/m11-iscx-external-evaluation.md](../../docs/m11-iscx-external-evaluation.md)。该评测只覆盖业务分类维度，不代表 VPN 状态分类，也不替代验收闭环中的 M11 证据。

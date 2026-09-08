# M4 消息聚类

当前状态：轻量 DBSCAN 基线已实现；参数已在合成真值和两个真实 DAT 上验证。真实样本结果是统计相似组，语义仍需结合协议知识人工解释。

输入是 M03 的 `framing.json` 及其消息 artifacts。距离是三部分的加权平均：

- 消息长度相对差；
- 256 维归一化字节直方图的总变差距离；
- 固定前缀范围内的逐位置不匹配比例，缺失位置显式计为不匹配。

DBSCAN 不要求预先指定簇数，离群消息标为 `cluster_id=-1`。每个簇选择簇内距离和最小的真实消息作为代表，不生成不存在的平均字节串。

```powershell
python run.py <m03-output>\framing.json --output-dir <new-output-directory> `
  --eps 0.25 --min-samples 2 --prefix-length 16
python -m unittest discover -s tests -v
```

输出 `clusters.json` 包含消息映射、代表消息、噪声比例和轮廓系数。传入 `--truth-labels labels.json` 时还会计算 ARI 与几何均值归一化的 NMI。标签 JSON 格式为 `{ "message-id": "expected-class" }`。真实 DAT 的固定参数和结果见 `data/external/validation.md`。

实现构造完整预计算距离矩阵，时间和内存均为 O(n²)，默认拒绝超过 1000 条消息。簇只表示所选距离下的统计相似性，不等于协议类型、字段语义或业务类别。

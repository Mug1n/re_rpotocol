# M6 字段边界与格式推断

当前状态：可解释的对齐列统计基线已实现。输入为 M05 `alignments.json`，输出固定、可变、可选、稀疏或样本不足的连续列区间，并在严格条件下提出整数长度关系假设。

```powershell
python run.py <m05-output>\alignments.json --output-dir <new-output-directory> `
  --min-cluster-samples 2 --min-presence-ratio 0.5 `
  --length-widths 1,2,4 --min-relation-samples 3
python -m unittest discover -s tests -v
```

每列记录支持数、gap 数、出现率、不同取值数、熵和最高频字节；相邻且分类、来源类型相同的列合并为字段候选。边界候选记录分类变化、参考/插入转换和相邻列熵变化。所有范围均为半开区间。

长度假设只检查对齐后仍对应连续原始字节的 1/2/4/8 字节窗口，同时要求至少指定数量的样本、消息长度至少两个取值、解码值至少两个取值，并且每条观测精确满足关系。支持总消息长度、字段后剩余字节数或“消息长度减固定开销”；大小端分别报告。

这些结果是结构候选，不是字段语义真值。少量样本、M04 混簇、M05 低质量对齐、压缩或密文都会制造碎片化或偶然关系；应结合原始偏移、反例和协议知识复核。

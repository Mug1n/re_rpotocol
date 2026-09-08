# M2 二进制基础特征分析

当前状态：标准库基线已实现，等待真实 DAT 与更大数据规模验证。

功能包括：长度、256 维字节计数/频率、Shannon 熵、可打印 ASCII/空白/零字节比例、高频字节、前缀预览、重叠 n-gram 重复模式，以及包含短尾窗的滑动窗口统计。所有窗口使用零起点半开区间。

```powershell
python run.py <input> --output-dir <new-output-directory>
python -m unittest discover -s tests -v
```

输出为 `<new-output-directory>/features.json`。输出目录必须不存在，避免覆盖既有实验结果。高熵只作为压缩、加密或随机数据的候选信号，不构成加密判定。
